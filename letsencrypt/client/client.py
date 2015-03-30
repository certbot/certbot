"""ACME protocol client class and helper functions."""
import logging
import os
import sys

import Crypto.PublicKey.RSA
import M2Crypto

from letsencrypt.acme import messages
from letsencrypt.acme import util as acme_util

from letsencrypt.client import auth_handler
from letsencrypt.client import continuity_auth
from letsencrypt.client import crypto_util
from letsencrypt.client import errors
from letsencrypt.client import le_util
from letsencrypt.client import network
from letsencrypt.client import reverter
from letsencrypt.client import revoker

from letsencrypt.client.apache import configurator
from letsencrypt.client.display import ops as display_ops
from letsencrypt.client.display import enhancements


class Client(object):
    """ACME protocol client.

    :ivar network: Network object for sending and receiving messages
    :type network: :class:`letsencrypt.client.network.Network`

    :ivar authkey: Authorization Key
    :type authkey: :class:`letsencrypt.client.le_util.Key`

    :ivar auth_handler: Object that supports the IAuthenticator interface.
        auth_handler contains both a dv_authenticator and a
        continuity_authenticator
    :type auth_handler: :class:`letsencrypt.client.auth_handler.AuthHandler`

    :ivar installer: Object supporting the IInstaller interface.
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.client.interfaces.IConfig`

    """

    def __init__(self, config, authkey, dv_auth, installer):
        """Initialize a client.

        :param dv_auth: IAuthenticator that can solve the
            :const:`letsencrypt.client.constants.DV_CHALLENGES`.
            The :meth:`~letsencrypt.client.interfaces.IAuthenticator.prepare`
            must have already been run.
        :type dv_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

        """
        self.network = network.Network(config.server)
        self.authkey = authkey
        self.installer = installer
        self.config = config

        if dv_auth is not None:
            cont_auth = continuity_auth.ContinuityAuthenticator(config)
            self.auth_handler = auth_handler.AuthHandler(
                dv_auth, cont_auth, self.network)
        else:
            self.auth_handler = None

    def obtain_certificate(self, domains, csr=None):
        """Obtains a certificate from the ACME server.

        :param str domains: list of domains to get a certificate

        :param csr: CSR must contain requested domains, the key used to generate
            this CSR can be different than self.authkey
        :type csr: :class:`CSR`

        :returns: cert_file, chain_file (paths to respective files)
        :rtype: `tuple` of `str`

        """
        if self.auth_handler is None:
            logging.warning("Unable to obtain a certificate, because client "
                            "does not have a valid auth handler.")

        # Request Challenges
        for name in domains:
            self.auth_handler.add_chall_msg(
                name, self.acme_challenge(name), self.authkey)

        # Perform Challenges/Get Authorizations
        self.auth_handler.get_authorizations()

        # Create CSR from names
        if csr is None:
            csr = init_csr(self.authkey, domains, self.config.cert_dir)

        # Retrieve certificate
        certificate_msg = self.acme_certificate(csr.data)

        # Save Certificate
        cert_file, chain_file = self.save_certificate(
            certificate_msg, self.config.cert_path, self.config.chain_path)

        revoker.Revoker.store_cert_key(
            cert_file, self.authkey.file, self.config)

        return cert_file, chain_file

    def acme_challenge(self, domain):
        """Handle ACME "challenge" phase.

        :returns: ACME "challenge" message.
        :rtype: :class:`letsencrypt.acme.messages.Challenge`

        """
        return self.network.send_and_receive_expected(
            messages.ChallengeRequest(identifier=domain),
            messages.Challenge)

    def acme_certificate(self, csr_der):
        """Handle ACME "certificate" phase.

        :param str csr_der: CSR in DER format.

        :returns: ACME "certificate" message.
        :rtype: :class:`letsencrypt.acme.message.Certificate`

        """
        logging.info("Preparing and sending CSR...")
        return self.network.send_and_receive_expected(
            messages.CertificateRequest.create(
                csr=acme_util.ComparableX509(
                    M2Crypto.X509.load_request_der_string(csr_der)),
                key=Crypto.PublicKey.RSA.importKey(self.authkey.pem)),
            messages.Certificate)

    def save_certificate(self, certificate_msg, cert_path, chain_path):
        # pylint: disable=no-self-use
        """Saves the certificate received from the ACME server.

        :param certificate_msg: ACME "certificate" message from server.
        :type certificate_msg: :class:`letsencrypt.acme.messages.Certificate`

        :param str cert_path: Path to attempt to save the cert file
        :param str chain_path: Path to attempt to save the chain file

        :returns: cert_file, chain_file (absolute paths to the actual files)
        :rtype: `tuple` of `str`

        :raises IOError: If unable to find room to write the cert files

        """
        cert_chain_abspath = None
        cert_fd, cert_file = le_util.unique_file(cert_path, 0o644)
        cert_fd.write(certificate_msg.certificate.as_pem())
        cert_fd.close()
        logging.info(
            "Server issued certificate; certificate written to %s", cert_file)

        if certificate_msg.chain:
            chain_fd, chain_fn = le_util.unique_file(chain_path, 0o644)
            for cert in certificate_msg.chain:
                chain_fd.write(cert.to_pem())
            chain_fd.close()

            logging.info("Cert chain written to %s", chain_fn)

            # This expects a valid chain file
            cert_chain_abspath = os.path.abspath(chain_fn)

        return os.path.abspath(cert_file), cert_chain_abspath

    def deploy_certificate(self, domains, privkey, cert_file, chain_file=None):
        """Install certificate

        :param list domains: list of domains to install the certificate

        :param privkey: private key for certificate
        :type privkey: :class:`letsencrypt.client.le_util.Key`

        :param str cert_file: certificate file path
        :param str chain_file: chain file path

        """
        if self.installer is None:
            logging.warning("No installer specified, client is unable to deploy"
                            "the certificate")
            raise errors.LetsEncryptClientError("No installer available")

        chain = None if chain_file is None else os.path.abspath(chain_file)

        for dom in domains:
            self.installer.deploy_cert(dom,
                                       os.path.abspath(cert_file),
                                       os.path.abspath(privkey.file),
                                       chain)

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


def init_key(key_size, key_dir):
    """Initializes privkey.

    Inits key and CSR using provided files or generating new files
    if necessary. Both will be saved in PEM format on the
    filesystem. The CSR is placed into DER format to allow
    the namedtuple to easily work with the protocol.

    :param str key_dir: Key save directory.

    """
    try:
        key_pem = crypto_util.make_key(key_size)
    except ValueError as err:
        logging.fatal(str(err))
        sys.exit(1)

    # Save file
    le_util.make_or_verify_dir(key_dir, 0o700)
    key_f, key_filename = le_util.unique_file(
        os.path.join(key_dir, "key-letsencrypt.pem"), 0o600)
    key_f.write(key_pem)
    key_f.close()

    logging.info("Generating key (%d bits): %s", key_size, key_filename)

    return le_util.Key(key_filename, key_pem)


def init_csr(privkey, names, cert_dir):
    """Initialize a CSR with the given private key.

    :param privkey: Key to include in the CSR
    :type privkey: :class:`letsencrypt.client.le_util.Key`

    :param list names: `str` names to include in the CSR

    :param str cert_dir: Certificate save directory.

    """
    csr_pem, csr_der = crypto_util.make_csr(privkey.pem, names)

    # Save CSR
    le_util.make_or_verify_dir(cert_dir, 0o755)
    csr_f, csr_filename = le_util.unique_file(
        os.path.join(cert_dir, "csr-letsencrypt.pem"), 0o644)
    csr_f.write(csr_pem)
    csr_f.close()

    logging.info("Creating CSR: %s", csr_filename)

    return le_util.CSR(csr_filename, csr_der, "der")


# This should be controlled by commandline parameters
def determine_authenticator(all_auths):
    """Returns a valid IAuthenticator.

    :param list all_auths: Where each is a
        :class:`letsencrypt.client.interfaces.IAuthenticator` object

    :returns: Valid Authenticator object or None

    :raises letsencrypt.client.errors.LetsEncryptClientError: If no
        authenticator is available.

    """
    # Available Authenticator objects
    avail_auths = []
    # Error messages for misconfigured authenticators
    errs = {}

    for pot_auth in all_auths:
        try:
            pot_auth.prepare()
        except errors.LetsEncryptMisconfigurationError as err:
            errs[pot_auth] = err
        except errors.LetsEncryptNoInstallationError:
            continue
        avail_auths.append(pot_auth)

    if len(avail_auths) > 1:
        auth = display_ops.choose_authenticator(avail_auths, errs)
    elif len(avail_auths) == 1:
        auth = avail_auths[0]
    else:
        raise errors.LetsEncryptClientError("No Authenticators available.")

    if auth is not None and auth in errs:
        logging.error("Please fix the configuration for the Authenticator. "
                      "The following error message was received: "
                      "%s", errs[auth])
        return

    return auth


def determine_installer(config):
    """Returns a valid installer if one exists.

    :param config: Configuration.
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    :returns: IInstaller or `None`
    :rtype: :class:`~letsencrypt.client.interfaces.IInstaller` or `None`

    """
    installer = configurator.ApacheConfigurator(config)
    try:
        installer.prepare()
        return installer
    except errors.LetsEncryptNoInstallationError:
        logging.info("Unable to find a way to install the certificate.")
        return
    except errors.LetsEncryptMisconfigurationError:
        # This will have to be changed in the future...
        return installer


def rollback(checkpoints, config):
    """Revert configuration the specified number of checkpoints.

    :param int checkpoints: Number of checkpoints to revert.

    :param config: Configuration.
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    """
    # Misconfigurations are only a slight problems... allow the user to rollback
    installer = determine_installer(config)

    # No Errors occurred during init... proceed normally
    # If installer is None... couldn't find an installer... there shouldn't be
    # anything to rollback
    if installer is not None:
        installer.rollback_checkpoints(checkpoints)
        installer.restart()


def revoke(config, no_confirm, cert, authkey):
    """Revoke certificates.

    :param config: Configuration.
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    """
    # Misconfigurations don't really matter. Determine installer better choose
    # correctly though.
    # This will need some better prepared or properly configured parameter...
    # I will figure it out later...
    installer = determine_installer(config)

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
