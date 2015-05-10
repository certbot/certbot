"""ACME protocol client class and helper functions."""
import logging
import os
import pkg_resources

import M2Crypto
import zope.component

from letsencrypt.acme import jose
from letsencrypt.acme.jose import jwk

from letsencrypt.client import account
from letsencrypt.client import auth_handler
from letsencrypt.client import continuity_auth
from letsencrypt.client import crypto_util
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util
from letsencrypt.client import network2
from letsencrypt.client import renewer
from letsencrypt.client import reverter
from letsencrypt.client import revoker

from letsencrypt.client.display import ops as display_ops
from letsencrypt.client.display import enhancements


class Client(object):
    """ACME protocol client.

    :ivar network: Network object for sending and receiving messages
    :type network: :class:`letsencrypt.client.network2.Network`

    :ivar account: Account object used for registration
    :type account: :class:`letsencrypt.client.account.Account`

    :ivar auth_handler: Object that supports the IAuthenticator interface.
        auth_handler contains both a dv_authenticator and a
        continuity_authenticator
    :type auth_handler: :class:`letsencrypt.client.auth_handler.AuthHandler`

    :ivar installer: Object supporting the IInstaller interface.
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.client.interfaces.IConfig`

    """

    def __init__(self, config, account_, dv_auth, installer):
        """Initialize a client.

        :param dv_auth: IAuthenticator that can solve the
            :const:`letsencrypt.client.constants.DV_CHALLENGES`.
            The :meth:`~letsencrypt.client.interfaces.IAuthenticator.prepare`
            must have already been run.
        :type dv_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

        """
        self.account = account_

        self.installer = installer

        # TODO: Allow for other alg types besides RS256
        self.network = network2.Network(
            config.server_url, jwk.JWKRSA.load(self.account.key.pem))

        self.config = config

        # TODO: Check if self.config.enroll_autorenew is None. If
        # so, set it based to the default: figure out if dv_auth is
        # standalone (then default is False, otherwise default is True)

        if dv_auth is not None:
            cont_auth = continuity_auth.ContinuityAuthenticator(config)
            self.auth_handler = auth_handler.AuthHandler(
                dv_auth, cont_auth, self.network, self.account)
        else:
            self.auth_handler = None

    def register(self):
        """New Registration with the ACME server."""
        self.account = self.network.register_from_account(self.account)
        if self.account.terms_of_service is not None:
            if not self.config.tos:
                # TODO: Replace with self.account.terms_of_service
                eula = pkg_resources.resource_string("letsencrypt", "EULA")
                agree = zope.component.getUtility(interfaces.IDisplay).yesno(
                    eula, "Agree", "Cancel")
            else:
                agree = True

            if agree:
                self.account.regr = self.network.agree_to_tos(self.account.regr)
            else:
                # What is the proper response here...
                raise errors.LetsEncryptClientError("Must agree to TOS")

        self.account.save()

    def _obtain_certificate(self, domains, csr=None):
        """Obtains a certificate from the ACME server.

        :meth:`.register` must be called before :meth:`.obtain_certificate`

        .. todo:: This function does not currently handle csr correctly...

        :param set domains: domains to get a certificate

        :param bool renewal: whether this request is a renewal (which avoids
            attempting to enroll the resulting certificate in the renewal
            database)

        :param csr: CSR must contain requested domains, the key used to generate
            this CSR can be different than self.authkey
        :type csr: :class:`CSR`

        :returns: cert_key, cert_path, chain_path
        :rtype: `tuple` of (:class:`letsencrypt.client.le_util.Key`, str, str)

        """
        if self.auth_handler is None:
            msg = ("Unable to obtain certificate because authenticator is "
                   "not set.")
            logging.warning(msg)
            raise errors.LetsEncryptClientError(msg)
        if self.account.regr is None:
            raise errors.LetsEncryptClientError(
                "Please register with the ACME server first.")

        # Perform Challenges/Get Authorizations
        authzr = self.auth_handler.get_authorizations(domains)

        # Create CSR from names
        cert_key = crypto_util.init_save_key(
            self.config.rsa_key_size, self.config.key_dir)
        csr = crypto_util.init_save_csr(
            cert_key, domains, self.config.cert_dir)

        # Retrieve certificate
        certr = self.network.request_issuance(
            jose.ComparableX509(
                M2Crypto.X509.load_request_der_string(csr.data)),
            authzr)

        cert_pem = certr.body.as_pem()
        chain_pem = None
        if certr.cert_chain_uri:
            chain_pem = self.network.fetch_chain(certr)

        if chain_pem is None:
            # XXX: just to stop RenewableCert from complaining; this is
            #      probably not a good solution
            chain_pem = ""
        else:
            chain_pem = chain_pem.as_pem()

        return cert_pem, cert_key.pem, chain_pem

    def obtain_and_enroll_certificate(self, domains, csr=None):
        cert_pem, privkey, chain_pem = self._obtain_certificate(domains, csr)
        return renewer.RenewableCert.new_lineage(domains[0], cert_pem,
                                                 privkey, chain_pem, None,
                                                 vars(self.config.namespace))
        # XXX: self.account.key.file is totally wrong here, that's
        #      the account key and not the cert key!

    def obtain_certificate(self, domains):
        return self._obtain_certificate(domains, None)

    def save_certificate(self, certr, cert_path, chain_path):
        # pylint: disable=no-self-use
        """Saves the certificate received from the ACME server.

        :param certr: ACME "certifica" resource.
        :type certr: :class:`letsencrypt.acme.messages.Certificate`

        :param str cert_path: Path to attempt to save the cert file
        :param str chain_path: Path to attempt to save the chain file

        :returns: cert_path, chain_path (absolute paths to the actual files)
        :rtype: `tuple` of `str`

        :raises IOError: If unable to find room to write the cert files

        """
        # try finally close
        cert_chain_abspath = None
        cert_file, act_cert_path = le_util.unique_file(cert_path, 0o644)
        # TODO: Except
        cert_pem = certr.body.as_pem()
        try:
            cert_file.write(cert_pem)
        finally:
            cert_file.close()
        logging.info("Server issued certificate; certificate written to %s",
                     act_cert_path)

        if certr.cert_chain_uri is not None:
            # TODO: Except
            chain_cert = self.network.fetch_chain(certr)
            if chain_cert is not None:
                chain_file, act_chain_path = le_util.unique_file(
                    chain_path, 0o644)
                chain_pem = chain_cert.as_pem()
                try:
                    chain_file.write(chain_pem)
                finally:
                    chain_file.close()

                logging.info("Cert chain written to %s", act_chain_path)

                # This expects a valid chain file
                cert_chain_abspath = os.path.abspath(act_chain_path)

        return os.path.abspath(act_cert_path), cert_chain_abspath

    def deploy_certificate(self, domains, lineage):
        """Install certificate

        :param list domains: list of domains to install the certificate

        :param lineage: RenewableCert object representing the certificate
        """
        if self.installer is None:
            logging.warning("No installer specified, client is unable to deploy"
                            "the certificate")
            raise errors.LetsEncryptClientError("No installer available")

        # TODO: Is it possible not to have a chain at all? (The
        # RenewableCert class currently doesn't support this case, but
        # perhaps the CA can issue according to ACME without providing
        # a chain, which would currently be a problem for instantiating
        # RenewableCert, and subsequently also for this method.)

        for dom in domains:
            # TODO: Provide a fullchain reference for installers like
            #       nginx that want it
            self.installer.deploy_cert(dom,
                                       lineage.cert,
                                       lineage.privkey,
                                       lineage.chain)

        self.installer.save("Deployed Let's Encrypt Certificate")
        # sites may have been enabled / final cleanup
        self.installer.restart()

        display_ops.success_installation(domains)

    def enhance_config(self, domains, redirect=None):
        """Enhance the configuration.

        .. todo:: This needs to handle the specific enhancements offered by the
            installer. We will also have to find a method to pass in the chosen
            values efficiently.

        :param list domains: list of domains to configure

        :param redirect: If traffic should be forwarded from HTTP to HTTPS.
        :type redirect: bool or None

        :raises letsencrypt.client.errors.LetsEncryptClientError: if
            no installer is specified in the client.

        """
        if self.installer is None:
            logging.warning("No installer is specified, there isn't any "
                            "configuration to enhance.")
            raise errors.LetsEncryptClientError("No installer available")

        if redirect is None:
            redirect = enhancements.ask("redirect")

        if redirect:
            self.redirect_to_ssl(domains)

    def redirect_to_ssl(self, domains):
        """Redirect all traffic from HTTP to HTTPS

        :param vhost: list of ssl_vhosts
        :type vhost: :class:`letsencrypt.client.interfaces.IInstaller`

        """
        for dom in domains:
            try:
                self.installer.enhance(dom, "redirect")
            except errors.LetsEncryptConfiguratorError:
                logging.warn("Unable to perform redirect for %s", dom)

        self.installer.save("Add Redirects")
        self.installer.restart()


def validate_key_csr(privkey, csr=None):
    """Validate Key and CSR files.

    Verifies that the client key and csr arguments are valid and correspond to
    one another. This does not currently check the names in the CSR due to
    the inability to read SANs from CSRs in python crypto libraries.

    If csr is left as None, only the key will be validated.

    :param privkey: Key associated with CSR
    :type privkey: :class:`letsencrypt.client.le_util.Key`

    :param csr: CSR
    :type csr: :class:`letsencrypt.client.le_util.CSR`

    :raises letsencrypt.client.errors.LetsEncryptClientError: when
        validation fails

    """
    # TODO: Handle all of these problems appropriately
    # The client can eventually do things like prompt the user
    # and allow the user to take more appropriate actions

    # Key must be readable and valid.
    if privkey.pem and not crypto_util.valid_privkey(privkey.pem):
        raise errors.LetsEncryptClientError(
            "The provided key is not a valid key")

    if csr:
        if csr.form == "der":
            csr_obj = M2Crypto.X509.load_request_der_string(csr.data)
            csr = le_util.CSR(csr.file, csr_obj.as_pem(), "der")

        # If CSR is provided, it must be readable and valid.
        if csr.data and not crypto_util.valid_csr(csr.data):
            raise errors.LetsEncryptClientError(
                "The provided CSR is not a valid CSR")

        # If both CSR and key are provided, the key must be the same key used
        # in the CSR.
        if csr.data and privkey.pem:
            if not crypto_util.csr_matches_pubkey(
                    csr.data, privkey.pem):
                raise errors.LetsEncryptClientError(
                    "The key and CSR do not match")


def determine_account(config):
    """Determine which account to use.

    Will create an account if necessary.

    :param config: Configuration object
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    :returns: Account
    :rtype: :class:`letsencrypt.client.account.Account`

    """
    accounts = account.Account.get_accounts(config)

    if len(accounts) == 1:
        return accounts[0]
    elif len(accounts) > 1:
        return display_ops.choose_account(accounts)

    return account.Account.from_prompts(config)


def rollback(default_installer, checkpoints, config, plugins):
    """Revert configuration the specified number of checkpoints.

    :param int checkpoints: Number of checkpoints to revert.

    :param config: Configuration.
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    """
    # Misconfigurations are only a slight problems... allow the user to rollback
    installer = display_ops.pick_installer(
        config, default_installer, plugins, question="Which installer "
        "should be used for rollback?")

    # No Errors occurred during init... proceed normally
    # If installer is None... couldn't find an installer... there shouldn't be
    # anything to rollback
    if installer is not None:
        installer.rollback_checkpoints(checkpoints)
        installer.restart()


def revoke(default_installer, config, plugins, no_confirm, cert, authkey):
    """Revoke certificates.

    :param config: Configuration.
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    """
    installer = display_ops.pick_installer(
        config, default_installer, plugins, question="Which installer "
        "should be used for certificate revocation?")

    revoc = revoker.Revoker(installer, config, no_confirm)
    # Cert is most selective, so it is chosen first.
    if cert is not None:
        revoc.revoke_from_cert(cert[0])
    elif authkey is not None:
        revoc.revoke_from_key(le_util.Key(authkey[0], authkey[1]))
    else:
        revoc.revoke_from_menu()


def view_config_changes(config):
    """View checkpoints and associated configuration changes.

    .. note:: This assumes that the installation is using a Reverter object.

    :param config: Configuration.
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    """
    rev = reverter.Reverter(config)
    rev.recovery_routine()
    rev.view_config_changes()
