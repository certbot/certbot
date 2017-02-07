"""Certbot client API."""
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL
import zope.component

from acme import client as acme_client
from acme import jose
from acme import messages

import certbot

from certbot import account
from certbot import auth_handler
from certbot import cli
from certbot import constants
from certbot import crypto_util
from certbot import eff
from certbot import error_handler
from certbot import errors
from certbot import interfaces
from certbot import reverter
from certbot import storage
from certbot import util

from certbot.display import ops as display_ops
from certbot.display import enhancements
from certbot.plugins import selection as plugin_selection


logger = logging.getLogger(__name__)


def acme_from_config_key(config, key):
    "Wrangle ACME client construction"
    # TODO: Allow for other alg types besides RS256
    net = acme_client.ClientNetwork(key, verify_ssl=(not config.no_verify_ssl),
                                    user_agent=determine_user_agent(config))
    return acme_client.Client(config.server, key=key, net=net)


def determine_user_agent(config):
    """
    Set a user_agent string in the config based on the choice of plugins.
    (this wasn't knowable at construction time)

    :returns: the client's User-Agent string
    :rtype: `str`
    """

    if config.user_agent is None:
        ua = "CertbotACMEClient/{0} ({1}) Authenticator/{2} Installer/{3}"
        ua = ua.format(certbot.__version__, util.get_os_info_ua(),
                       config.authenticator, config.installer)
    else:
        ua = config.user_agent
    return ua

def sample_user_agent():
    "Document what this Certbot's user agent string will be like."
    class DummyConfig(object):
        "Shim for computing a sample user agent."
        def __init__(self):
            self.authenticator = "XXX"
            self.installer = "YYY"
            self.user_agent = None
    return determine_user_agent(DummyConfig())


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
        client action is necessary, i.e. when ``terms_of_service is not
        None``. This argument is optional, if not supplied it will
        default to automatic acceptance!

    :raises certbot.errors.Error: In case of any client problems, in
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
        if not config.register_unsafely_without_email:
            msg = ("No email was provided and "
                   "--register-unsafely-without-email was not present.")
            logger.warning(msg)
            raise errors.Error(msg)
        if not config.dry_run:
            logger.warning("Registering without email!")

    # Each new registration shall use a fresh new key
    key = jose.JWKRSA(key=jose.ComparableRSAKey(
        rsa.generate_private_key(
            public_exponent=65537,
            key_size=config.rsa_key_size,
            backend=default_backend())))
    acme = acme_from_config_key(config, key)
    # TODO: add phone?
    regr = perform_registration(acme, config)

    if regr.terms_of_service is not None:
        if tos_cb is not None and not tos_cb(regr):
            raise errors.Error(
                "Registration cannot proceed without accepting "
                "Terms of Service.")
        regr = acme.agree_to_tos(regr)

    acc = account.Account(regr, key)
    account.report_new_account(acc, config)
    account_storage.save(acc)

    eff.handle_subscription(config)

    return acc, acme


def perform_registration(acme, config):
    """
    Actually register new account, trying repeatedly if there are email
    problems

    :param .IConfig config: Client configuration.
    :param acme.client.Client client: ACME client object.

    :returns: Registration Resource.
    :rtype: `acme.messages.RegistrationResource`

    :raises .UnexpectedUpdate:
    """
    try:
        return acme.register(messages.NewRegistration.from_data(email=config.email))
    except messages.Error as e:
        if e.code == "invalidEmail" or e.code == "invalidContact":
            if config.noninteractive_mode:
                msg = ("The ACME server believes %s is an invalid email address. "
                       "Please ensure it is a valid email and attempt "
                       "registration again." % config.email)
                raise errors.Error(msg)
            else:
                config.namespace.email = display_ops.get_email(invalid=True)
                return perform_registration(acme, config)
        else:
            raise


class Client(object):
    """Certbot's client.

    :ivar .IConfig config: Client configuration.
    :ivar .Account account: Account registered with `register`.
    :ivar .AuthHandler auth_handler: Authorizations handler that will
        dispatch DV challenges to appropriate authenticators
        (providing `.IAuthenticator` interface).
    :ivar .IAuthenticator auth: Prepared (`.IAuthenticator.prepare`)
        authenticator that can solve ACME challenges.
    :ivar .IInstaller installer: Installer.
    :ivar acme.client.Client acme: Optional ACME client API handle.
       You might already have one from `register`.

    """

    def __init__(self, config, account_, auth, installer, acme=None):
        """Initialize a client."""
        self.config = config
        self.account = account_
        self.auth = auth
        self.installer = installer

        # Initialize ACME if account is provided
        if acme is None and self.account is not None:
            acme = acme_from_config_key(config, self.account.key)
        self.acme = acme

        if auth is not None:
            self.auth_handler = auth_handler.AuthHandler(
                auth, self.acme, self.account, self.config.pref_challs)
        else:
            self.auth_handler = None

    def obtain_certificate_from_csr(self, domains, csr,
        typ=OpenSSL.crypto.FILETYPE_ASN1, authzr=None):
        """Obtain certificate.

        Internal function with precondition that `domains` are
        consistent with identifiers present in the `csr`.

        :param list domains: Domain names.
        :param .util.CSR csr: DER-encoded Certificate Signing
            Request. The key used to generate this CSR can be different
            than `authkey`.
        :param list authzr: List of
            :class:`acme.messages.AuthorizationResource`

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

        if authzr is None:
            authzr = self.auth_handler.get_authorizations(domains)

        certr = self.acme.request_issuance(
            jose.ComparableX509(
                OpenSSL.crypto.load_certificate_request(typ, csr.data)),
                authzr)
        return certr, self.acme.fetch_chain(certr)

    def obtain_certificate(self, domains):
        """Obtains a certificate from the ACME server.

        `.register` must be called before `.obtain_certificate`

        :param list domains: domains to get a certificate

        :returns: `.CertificateResource`, certificate chain (as
            returned by `.fetch_chain`), and newly generated private key
            (`.util.Key`) and DER-encoded Certificate Signing Request
            (`.util.CSR`).
        :rtype: tuple

        """
        authzr = self.auth_handler.get_authorizations(
                domains,
                self.config.allow_subset_of_names)

        auth_domains = set(a.body.identifier.value for a in authzr)
        domains = [d for d in domains if d in auth_domains]

        # Create CSR from names
        key = crypto_util.init_save_key(
            self.config.rsa_key_size, self.config.key_dir)
        csr = crypto_util.init_save_csr(key, domains, self.config.csr_dir)

        return (self.obtain_certificate_from_csr(domains, csr, authzr=authzr)
                                                                + (key, csr))

    def obtain_and_enroll_certificate(self, domains, certname):
        """Obtain and enroll certificate.

        Get a new certificate for the specified domains using the specified
        authenticator and installer, and then create a new renewable lineage
        containing it.

        :param list domains: Domains to request.
        :param plugins: A PluginsFactory object.
        :param str certname: Name of new cert

        :returns: A new :class:`certbot.storage.RenewableCert` instance
            referred to the enrolled cert lineage, False if the cert could not
            be obtained, or None if doing a successful dry run.

        """
        certr, chain, key, _ = self.obtain_certificate(domains)

        if (self.config.config_dir != constants.CLI_DEFAULTS["config_dir"] or
                self.config.work_dir != constants.CLI_DEFAULTS["work_dir"]):
            logger.warning(
                "Non-standard path(s), might not work with crontab installed "
                "by your operating system package manager")

        new_name = certname if certname else domains[0]
        if self.config.dry_run:
            logger.debug("Dry run: Skipping creating new lineage for %s",
                        new_name)
            return None
        else:
            return storage.RenewableCert.new_lineage(
                new_name, OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, certr.body.wrapped),
                key.pem, crypto_util.dump_pyopenssl_chain(chain),
                self.config)

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
            util.make_or_verify_dir(
                os.path.dirname(path), 0o755, os.geteuid(),
                self.config.strict_permissions)

        cert_pem = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, certr.body.wrapped)

        cert_file, abs_cert_path = _open_pem_file('cert_path', cert_path)

        try:
            cert_file.write(cert_pem)
        finally:
            cert_file.close()
        logger.info("Server issued certificate; certificate written to %s",
                    abs_cert_path)

        if not chain_cert:
            return abs_cert_path, None, None
        else:
            chain_pem = crypto_util.dump_pyopenssl_chain(chain_cert)

            chain_file, abs_chain_path =\
                    _open_pem_file('chain_path', chain_path)
            fullchain_file, abs_fullchain_path =\
                    _open_pem_file('fullchain_path', fullchain_path)

            _save_chain(chain_pem, chain_file)
            _save_chain(cert_pem + chain_pem, fullchain_file)

            return abs_cert_path, abs_chain_path, abs_fullchain_path

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

        msg = ("Unable to install the certificate")
        with error_handler.ErrorHandler(self._recovery_routine_with_msg, msg):
            for dom in domains:
                self.installer.deploy_cert(
                    domain=dom, cert_path=os.path.abspath(cert_path),
                    key_path=os.path.abspath(privkey_path),
                    chain_path=chain_path,
                    fullchain_path=fullchain_path)
                self.installer.save()  # needed by the Apache plugin

            self.installer.save("Deployed ACME Certificate")

        msg = ("We were unable to install your certificate, "
               "however, we successfully restored your "
               "server to its prior configuration.")
        with error_handler.ErrorHandler(self._rollback_and_restart, msg):
            # sites may have been enabled / final cleanup
            self.installer.restart()

    def enhance_config(self, domains, chain_path):
        """Enhance the configuration.

        :param list domains: list of domains to configure
        :param chain_path: chain file path
        :type chain_path: `str` or `None`

        :raises .errors.Error: if no installer is specified in the
            client.

        """
        if self.installer is None:
            logger.warning("No installer is specified, there isn't any "
                           "configuration to enhance.")
            raise errors.Error("No installer available")

        enhanced = False
        enhancement_info = (
            ("hsts", "ensure-http-header", "Strict-Transport-Security"),
            ("redirect", "redirect", None),
            ("staple", "staple-ocsp", chain_path),
            ("uir", "ensure-http-header", "Upgrade-Insecure-Requests"),)
        supported = self.installer.supported_enhancements()

        for config_name, enhancement_name, option in enhancement_info:
            config_value = getattr(self.config, config_name)
            if enhancement_name in supported:
                if config_name == "redirect" and config_value is None:
                    config_value = enhancements.ask(enhancement_name)
                if config_value:
                    self.apply_enhancement(domains, enhancement_name, option)
                    enhanced = True
            elif config_value:
                logger.warning(
                    "Option %s is not supported by the selected installer. "
                    "Skipping enhancement.", config_name)

        msg = ("We were unable to restart web server")
        if enhanced:
            with error_handler.ErrorHandler(self._rollback_and_restart, msg):
                self.installer.restart()

    def apply_enhancement(self, domains, enhancement, options=None):
        """Applies an enhancement on all domains.

        :param domains: list of ssl_vhosts
        :type list of str

        :param enhancement: name of enhancement, e.g. ensure-http-header
        :type str

        .. note:: when more options are need make options a list.
        :param options: options to enhancement, e.g. Strict-Transport-Security
        :type str

        :raises .errors.PluginError: If Enhancement is not supported, or if
            there is any other problem with the enhancement.


        """
        msg = ("We were unable to set up enhancement %s for your server, "
               "however, we successfully installed your certificate."
               % (enhancement))
        with error_handler.ErrorHandler(self._recovery_routine_with_msg, msg):
            for dom in domains:
                try:
                    self.installer.enhance(dom, enhancement, options)
                except errors.PluginEnhancementAlreadyPresent:
                    logger.warning("Enhancement %s was already set.",
                            enhancement)
                except errors.PluginError:
                    logger.warning("Unable to set enhancement %s for %s",
                            enhancement, dom)
                    raise

            self.installer.save("Add enhancement %s" % (enhancement))

    def _recovery_routine_with_msg(self, success_msg):
        """Calls the installer's recovery routine and prints success_msg

        :param str success_msg: message to show on successful recovery

        """
        self.installer.recovery_routine()
        reporter = zope.component.getUtility(interfaces.IReporter)
        reporter.add_message(success_msg, reporter.HIGH_PRIORITY)

    def _rollback_and_restart(self, success_msg):
        """Rollback the most recent checkpoint and restart the webserver

        :param str success_msg: message to show on successful rollback

        """
        logger.critical("Rolling back to previous server configuration...")
        reporter = zope.component.getUtility(interfaces.IReporter)
        try:
            self.installer.rollback_checkpoints()
            self.installer.restart()
        except:
            # TODO: suggest letshelp-letsencrypt here
            reporter.add_message(
                "An error occurred and we failed to restore your config and "
                "restart your server. Please submit a bug report to "
                "https://github.com/letsencrypt/letsencrypt",
                reporter.HIGH_PRIORITY)
            raise
        reporter.add_message(success_msg, reporter.HIGH_PRIORITY)


def validate_key_csr(privkey, csr=None):
    """Validate Key and CSR files.

    Verifies that the client key and csr arguments are valid and correspond to
    one another. This does not currently check the names in the CSR due to
    the inability to read SANs from CSRs in python crypto libraries.

    If csr is left as None, only the key will be validated.

    :param privkey: Key associated with CSR
    :type privkey: :class:`certbot.util.Key`

    :param .util.CSR csr: CSR

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
            csr = util.CSR(csr.file, OpenSSL.crypto.dump_certificate(
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
    :type config: :class:`certbot.interfaces.IConfig`

    """
    # Misconfigurations are only a slight problems... allow the user to rollback
    installer = plugin_selection.pick_installer(
        config, default_installer, plugins, question="Which installer "
        "should be used for rollback?")

    # No Errors occurred during init... proceed normally
    # If installer is None... couldn't find an installer... there shouldn't be
    # anything to rollback
    if installer is not None:
        installer.rollback_checkpoints(checkpoints)
        installer.restart()


def view_config_changes(config, num=None):
    """View checkpoints and associated configuration changes.

    .. note:: This assumes that the installation is using a Reverter object.

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`

    """
    rev = reverter.Reverter(config)
    rev.recovery_routine()
    rev.view_config_changes(num)

def _open_pem_file(cli_arg_path, pem_path):
    """Open a pem file.

    If cli_arg_path was set by the client, open that.
    Otherwise, uniquify the file path.

    :param str cli_arg_path: the cli arg name, e.g. cert_path
    :param str pem_path: the pem file path to open

    :returns: a tuple of file object and its absolute file path

    """
    if cli.set_by_cli(cli_arg_path):
        return util.safe_open(pem_path, chmod=0o644, mode="wb"),\
            os.path.abspath(pem_path)
    else:
        uniq = util.unique_file(pem_path, 0o644, "wb")
        return uniq[0], os.path.abspath(uniq[1])

def _save_chain(chain_pem, chain_file):
    """Saves chain_pem at a unique path based on chain_path.

    :param str chain_pem: certificate chain in PEM format
    :param str chain_file: chain file object

    """
    try:
        chain_file.write(chain_pem)
    finally:
        chain_file.close()

    logger.info("Cert chain written to %s", chain_file.name)
