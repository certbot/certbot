"""Let's Encrypt client API."""
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL

from acme import client as acme_client
from acme import jose
from acme import messages

from letsencrypt import account
from letsencrypt import auth_handler
from letsencrypt import configuration
from letsencrypt import constants
from letsencrypt import continuity_auth
from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import error_handler
from letsencrypt import le_util
from letsencrypt import reverter
from letsencrypt import storage

from letsencrypt.display import ops as display_ops
from letsencrypt.display import enhancements


logger = logging.getLogger(__name__)


def _acme_from_config_key(config, key):
    # TODO: Allow for other alg types besides RS256
    return acme_client.Client(directory=config.server, key=key,
                              verify_ssl=(not config.no_verify_ssl))


def register(config, account_storage, tos_cb=None):
    """Register new account with an ACME CA.

    This function takes care of generating fresh private key,
    registering the account, optionally accepting CA Terms of Service
    and finally saving the account. It should be called prior to
    initialization of `Client`, unless account has already been created.

    :param .IConfig config: Client configuration.

    :param .AccountStorage account_storage: Account storage where newly
        registered account will be saved to. Save happens only after TOS
        acceptance step, so any account private keys or
        `.RegistrationResource` will not be persisted if `tos_cb`
        returns ``False``.

    :param tos_cb: If ACME CA requires the user to accept a Terms of
        Service before registering account, client action is
        necessary. For example, a CLI tool would prompt the user
        acceptance. `tos_cb` must be a callable that should accept
        `.RegistrationResource` and return a `bool`: ``True`` iff the
        Terms of Service present in the contained
        `.Registration.terms_of_service` is accepted by the client, and
        ``False`` otherwise. ``tos_cb`` will be called only if the
        client acction is necessary, i.e. when ``terms_of_service is not
        None``. This argument is optional, if not supplied it will
        default to automatic acceptance!

    :raises letsencrypt.errors.Error: In case of any client problems, in
        particular registration failure, or unaccepted Terms of Service.
    :raises acme.errors.Error: In case of any protocol problems.

    :returns: Newly registered and saved account, as well as protocol
        API handle (should be used in `Client` initialization).
    :rtype: `tuple` of `.Account` and `acme.client.Client`

    """
    # Log non-standard actions, potentially wrong API calls
    if account_storage.find_all():
        logger.info("There are already existing accounts for %s", config.server)
    if config.email is None:
        logger.warn("Registering without email!")

    # Each new registration shall use a fresh new key
    key = jose.JWKRSA(key=jose.ComparableRSAKey(
        rsa.generate_private_key(
            public_exponent=65537,
            key_size=config.rsa_key_size,
            backend=default_backend())))
    acme = _acme_from_config_key(config, key)
    # TODO: add phone?
    regr = acme.register(messages.NewRegistration.from_data(email=config.email))

    if regr.terms_of_service is not None:
        if tos_cb is not None and not tos_cb(regr):
            raise errors.Error(
                "Registration cannot proceed without accepting "
                "Terms of Service.")
        regr = acme.agree_to_tos(regr)

    acc = account.Account(regr, key)
    account.report_new_account(acc, config)
    account_storage.save(acc)
    return acc, acme


class Client(object):
    """ACME protocol client.

    :ivar .IConfig config: Client configuration.
    :ivar .Account account: Account registered with `register`.
    :ivar .AuthHandler auth_handler: Authorizations handler that will
        dispatch DV and Continuity challenges to appropriate
        authenticators (providing `.IAuthenticator` interface).
    :ivar .IAuthenticator dv_auth: Prepared (`.IAuthenticator.prepare`)
        authenticator that can solve the `.constants.DV_CHALLENGES`.
    :ivar .IInstaller installer: Installer.
    :ivar acme.client.Client acme: Optional ACME client API handle.
       You might already have one from `register`.

    """

    def __init__(self, config, account_, dv_auth, installer, acme=None):
        """Initialize a client."""
        self.config = config
        self.account = account_
        self.dv_auth = dv_auth
        self.installer = installer

        # Initialize ACME if account is provided
        if acme is None and self.account is not None:
            acme = _acme_from_config_key(config, self.account.key)
        self.acme = acme

        # TODO: Check if self.config.enroll_autorenew is None. If
        # so, set it based to the default: figure out if dv_auth is
        # standalone (then default is False, otherwise default is True)

        if dv_auth is not None:
            cont_auth = continuity_auth.ContinuityAuthenticator(config,
                                                                installer)
            self.auth_handler = auth_handler.AuthHandler(
                dv_auth, cont_auth, self.acme, self.account)
        else:
            self.auth_handler = None

    def _obtain_certificate(self, domains, csr):
        """Obtain certificate.

        Internal function with precondition that `domains` are
        consistent with identifiers present in the `csr`.

        :param list domains: Domain names.
        :param .le_util.CSR csr: DER-encoded Certificate Signing
            Request. The key used to generate this CSR can be different
            than `authkey`.

        :returns: `.CertificateResource` and certificate chain (as
            returned by `.fetch_chain`).
        :rtype: tuple

        """
        if self.auth_handler is None:
            msg = ("Unable to obtain certificate because authenticator is "
                   "not set.")
            logger.warning(msg)
            raise errors.Error(msg)
        if self.account.regr is None:
            raise errors.Error("Please register with the ACME server first.")

        logger.debug("CSR: %s, domains: %s", csr, domains)

        authzr = self.auth_handler.get_authorizations(domains)
        certr = self.acme.request_issuance(
            jose.ComparableX509(OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1, csr.data)),
            authzr)
        return certr, self.acme.fetch_chain(certr)

    def obtain_certificate_from_csr(self, csr):
        """Obtain certficiate from CSR.

        :param .le_util.CSR csr: DER-encoded Certificate Signing
            Request.

        :returns: `.CertificateResource` and certificate chain (as
            returned by `.fetch_chain`).
        :rtype: tuple

        """
        return self._obtain_certificate(
            # TODO: add CN to domains?
            crypto_util.get_sans_from_csr(
                csr.data, OpenSSL.crypto.FILETYPE_ASN1), csr)

    def obtain_certificate(self, domains):
        """Obtains a certificate from the ACME server.

        `.register` must be called before `.obtain_certificate`

        :param set domains: domains to get a certificate

        :returns: `.CertificateResource`, certificate chain (as
            returned by `.fetch_chain`), and newly generated private key
            (`.le_util.Key`) and DER-encoded Certificate Signing Request
            (`.le_util.CSR`).
        :rtype: tuple

        """
        # Create CSR from names
        key = crypto_util.init_save_key(
            self.config.rsa_key_size, self.config.key_dir)
        csr = crypto_util.init_save_csr(key, domains, self.config.csr_dir)

        return self._obtain_certificate(domains, csr) + (key, csr)

    def obtain_and_enroll_certificate(self, domains, plugins):
        """Obtain and enroll certificate.

        Get a new certificate for the specified domains using the specified
        authenticator and installer, and then create a new renewable lineage
        containing it.

        :param list domains: Domains to request.
        :param plugins: A PluginsFactory object.

        :returns: A new :class:`letsencrypt.storage.RenewableCert` instance
            referred to the enrolled cert lineage, or False if the cert could
            not be obtained.

        """
        certr, chain, key, _ = self.obtain_certificate(domains)

        # TODO: remove this dirty hack
        self.config.namespace.authenticator = plugins.find_init(
            self.dv_auth).name
        if self.installer is not None:
            self.config.namespace.installer = plugins.find_init(
                self.installer).name

        # XXX: We clearly need a more general and correct way of getting
        # options into the configobj for the RenewableCert instance.
        # This is a quick-and-dirty way to do it to allow integration
        # testing to start.  (Note that the config parameter to new_lineage
        # ideally should be a ConfigObj, but in this case a dict will be
        # accepted in practice.)
        params = vars(self.config.namespace)
        config = {}
        cli_config = configuration.RenewerConfiguration(self.config.namespace)

        if (cli_config.config_dir != constants.CLI_DEFAULTS["config_dir"] or
                cli_config.work_dir != constants.CLI_DEFAULTS["work_dir"]):
            logger.warning(
                "Non-standard path(s), might not work with crontab installed "
                "by your operating system package manager")

        lineage = storage.RenewableCert.new_lineage(
            domains[0], OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, certr.body),
            key.pem, crypto_util.dump_pyopenssl_chain(chain),
            params, config, cli_config)
        return lineage

    def save_certificate(self, certr, chain_cert,
                         cert_path, chain_path, fullchain_path):
        """Saves the certificate received from the ACME server.

        :param certr: ACME "certificate" resource.
        :type certr: :class:`acme.messages.Certificate`

        :param list chain_cert:
        :param str cert_path: Candidate path to a certificate.
        :param str chain_path: Candidate path to a certificate chain.
        :param str fullchain_path: Candidate path to a full cert chain.

        :returns: cert_path, chain_path, and fullchain_path as absolute
            paths to the actual files
        :rtype: `tuple` of `str`

        :raises IOError: If unable to find room to write the cert files

        """
        for path in cert_path, chain_path, fullchain_path:
            le_util.make_or_verify_dir(
                os.path.dirname(path), 0o755, os.geteuid(),
                self.config.strict_permissions)

        cert_pem = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, certr.body)
        cert_file, act_cert_path = le_util.unique_file(cert_path, 0o644)
        try:
            cert_file.write(cert_pem)
        finally:
            cert_file.close()
        logger.info("Server issued certificate; certificate written to %s",
                    act_cert_path)

        cert_chain_abspath = None
        fullchain_abspath = None
        if chain_cert:
            chain_pem = crypto_util.dump_pyopenssl_chain(chain_cert)
            cert_chain_abspath = _save_chain(chain_pem, chain_path)
            fullchain_abspath = _save_chain(cert_pem + chain_pem,
                                            fullchain_path)

        return os.path.abspath(act_cert_path), cert_chain_abspath, fullchain_abspath

    def deploy_certificate(self, domains, privkey_path,
                           cert_path, chain_path, fullchain_path):
        """Install certificate

        :param list domains: list of domains to install the certificate
        :param str privkey_path: path to certificate private key
        :param str cert_path: certificate file path (optional)
        :param str chain_path: chain file path

        """
        if self.installer is None:
            logger.warning("No installer specified, client is unable to deploy"
                           "the certificate")
            raise errors.Error("No installer available")

        chain_path = None if chain_path is None else os.path.abspath(chain_path)

        with error_handler.ErrorHandler(self.installer.recovery_routine):
            for dom in domains:
                self.installer.deploy_cert(
                    domain=dom, cert_path=os.path.abspath(cert_path),
                    key_path=os.path.abspath(privkey_path),
                    chain_path=chain_path,
                    fullchain_path=fullchain_path)

            self.installer.save("Deployed Let's Encrypt Certificate")
            # sites may have been enabled / final cleanup
            self.installer.restart()

    def enhance_config(self, domains, redirect=None):
        """Enhance the configuration.

        .. todo:: This needs to handle the specific enhancements offered by the
            installer. We will also have to find a method to pass in the chosen
            values efficiently.

        :param list domains: list of domains to configure

        :param redirect: If traffic should be forwarded from HTTP to HTTPS.
        :type redirect: bool or None

        :raises .errors.Error: if no installer is specified in the
            client.

        """
        if self.installer is None:
            logger.warning("No installer is specified, there isn't any "
                           "configuration to enhance.")
            raise errors.Error("No installer available")

        if redirect is None:
            redirect = enhancements.ask("redirect")

        # When support for more enhancements are added, the call to the
        # plugin's `enhance` function should be wrapped by an ErrorHandler
        if redirect:
            self.redirect_to_ssl(domains)

    def redirect_to_ssl(self, domains):
        """Redirect all traffic from HTTP to HTTPS

        :param vhost: list of ssl_vhosts
        :type vhost: :class:`letsencrypt.interfaces.IInstaller`

        """
        with error_handler.ErrorHandler(self.installer.recovery_routine):
            for dom in domains:
                try:
                    self.installer.enhance(dom, "redirect")
                except errors.PluginError:
                    logger.warn("Unable to perform redirect for %s", dom)
                    raise

            self.installer.save("Add Redirects")
            self.installer.restart()


def validate_key_csr(privkey, csr=None):
    """Validate Key and CSR files.

    Verifies that the client key and csr arguments are valid and correspond to
    one another. This does not currently check the names in the CSR due to
    the inability to read SANs from CSRs in python crypto libraries.

    If csr is left as None, only the key will be validated.

    :param privkey: Key associated with CSR
    :type privkey: :class:`letsencrypt.le_util.Key`

    :param .le_util.CSR csr: CSR

    :raises .errors.Error: when validation fails

    """
    # TODO: Handle all of these problems appropriately
    # The client can eventually do things like prompt the user
    # and allow the user to take more appropriate actions

    # Key must be readable and valid.
    if privkey.pem and not crypto_util.valid_privkey(privkey.pem):
        raise errors.Error("The provided key is not a valid key")

    if csr:
        if csr.form == "der":
            csr_obj = OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1, csr.data)
            csr = le_util.CSR(csr.file, OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, csr_obj), "pem")

        # If CSR is provided, it must be readable and valid.
        if csr.data and not crypto_util.valid_csr(csr.data):
            raise errors.Error("The provided CSR is not a valid CSR")

        # If both CSR and key are provided, the key must be the same key used
        # in the CSR.
        if csr.data and privkey.pem:
            if not crypto_util.csr_matches_pubkey(
                    csr.data, privkey.pem):
                raise errors.Error("The key and CSR do not match")


def rollback(default_installer, checkpoints, config, plugins):
    """Revert configuration the specified number of checkpoints.

    :param int checkpoints: Number of checkpoints to revert.

    :param config: Configuration.
    :type config: :class:`letsencrypt.interfaces.IConfig`

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


def view_config_changes(config):
    """View checkpoints and associated configuration changes.

    .. note:: This assumes that the installation is using a Reverter object.

    :param config: Configuration.
    :type config: :class:`letsencrypt.interfaces.IConfig`

    """
    rev = reverter.Reverter(config)
    rev.recovery_routine()
    rev.view_config_changes()


def _save_chain(chain_pem, chain_path):
    """Saves chain_pem at a unique path based on chain_path.

    :param str chain_pem: certificate chain in PEM format
    :param str chain_path: candidate path for the cert chain

    :returns: absolute path to saved cert chain
    :rtype: str

    """
    chain_file, act_chain_path = le_util.unique_file(chain_path, 0o644)
    try:
        chain_file.write(chain_pem)
    finally:
        chain_file.close()

    logger.info("Cert chain written to %s", act_chain_path)

    # This expects a valid chain file
    return os.path.abspath(act_chain_path)
