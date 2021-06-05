"""Certbot main entry point."""
# pylint: disable=too-many-lines

import functools
import logging.handlers
import sys
from contextlib import contextmanager
from typing import Generator
from typing import IO
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

import configobj
import josepy as jose
import zope.component

from acme import errors as acme_errors
import certbot
from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import util
from certbot._internal import account
from certbot._internal import cert_manager
from certbot._internal import cli
from certbot._internal import client
from certbot._internal import configuration
from certbot._internal import constants
from certbot._internal import eff
from certbot._internal import hooks
from certbot._internal import log
from certbot._internal import renewal
from certbot._internal import reporter
from certbot._internal import snap_config
from certbot._internal import storage
from certbot._internal import updater
from certbot._internal.plugins import disco as plugins_disco
from certbot._internal.plugins import selection as plug_sel
from certbot.compat import filesystem
from certbot.compat import misc
from certbot.compat import os
from certbot.display import ops as display_ops
from certbot.display import util as display_util
from certbot.plugins import enhancements

USER_CANCELLED = ("User chose to cancel the operation and may "
                  "reinvoke the client.")


logger = logging.getLogger(__name__)


def _suggest_donation_if_appropriate(config):
    """Potentially suggest a donation to support Certbot.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :returns: `None`
    :rtype: None

    """
    assert config.verb != "renew"
    if config.staging:
        # --dry-run implies --staging
        return
    disp = zope.component.getUtility(interfaces.IDisplay)
    util.atexit_register(
        disp.notification,
        "If you like Certbot, please consider supporting our work by:\n"
        " * Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate\n"
        " * Donating to EFF:                    https://eff.org/donate-le",
        pause=False
    )


def _get_and_save_cert(le_client, config, domains=None, certname=None, lineage=None):
    """Authenticate and enroll certificate.

    This method finds the relevant lineage, figures out what to do with it,
    then performs that action. Includes calls to hooks, various reports,
    checks, and requests for user input.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param domains: List of domain names to get a certificate. Defaults to `None`
    :type domains: `list` of `str`

    :param certname: Name of new certificate. Defaults to `None`
    :type certname: str

    :param lineage: Certificate lineage object. Defaults to `None`
    :type lineage: storage.RenewableCert

    :returns: the issued certificate or `None` if doing a dry run
    :rtype: storage.RenewableCert or None

    :raises errors.Error: if certificate could not be obtained

    """
    hooks.pre_hook(config)
    try:
        if lineage is not None:
            # Renewal, where we already know the specific lineage we're
            # interested in
            display_util.notify(
                "{action} for {domains}".format(
                    action="Simulating renewal of an existing certificate"
                            if config.dry_run else "Renewing an existing certificate",
                    domains=display_util.summarize_domain_list(domains or lineage.names())
                )
            )
            renewal.renew_cert(config, domains, le_client, lineage)
        else:
            # TREAT AS NEW REQUEST
            assert domains is not None
            display_util.notify(
                "{action} for {domains}".format(
                    action="Simulating a certificate request" if config.dry_run else
                           "Requesting a certificate",
                    domains=display_util.summarize_domain_list(domains)
                )
            )
            lineage = le_client.obtain_and_enroll_certificate(domains, certname)
            if lineage is False:
                raise errors.Error("Certificate could not be obtained")
            if lineage is not None:
                hooks.deploy_hook(config, lineage.names(), lineage.live_dir)
    finally:
        hooks.post_hook(config)

    return lineage


def _handle_unexpected_key_type_migration(config: configuration.NamespaceConfig,
                                          cert: storage.RenewableCert) -> None:
    """
    This function ensures that the user will not implicitly migrate an existing key
    from one type to another in the situation where a certificate for that lineage
    already exist and they have not provided explicitly --key-type and --cert-name.
    :param config: Current configuration provided by the client
    :param cert: Matching certificate that could be renewed
    """
    if not cli.set_by_cli("key_type") or not cli.set_by_cli("certname"):

        new_key_type = config.key_type.upper()
        cur_key_type = cert.private_key_type.upper()

        if new_key_type != cur_key_type:
            msg = ('Are you trying to change the key type of the certificate named {0} '
                   'from {1} to {2}? Please provide both --cert-name and --key-type on '
                   'the command line confirm the change you are trying to make.')
            msg = msg.format(cert.lineagename, cur_key_type, new_key_type)
            raise errors.Error(msg)


def _handle_subset_cert_request(config: configuration.NamespaceConfig,
                                domains: List[str],
                                cert: storage.RenewableCert
                                ) -> Tuple[str, Optional[storage.RenewableCert]]:
    """Figure out what to do if a previous cert had a subset of the names now requested

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param domains: List of domain names
    :type domains: `list` of `str`

    :param cert: Certificate object
    :type cert: storage.RenewableCert

    :returns: Tuple of (str action, cert_or_None) as per _find_lineage_for_domains_and_certname
              action can be: "newcert" | "renew" | "reinstall"
    :rtype: `tuple` of `str`

    """
    _handle_unexpected_key_type_migration(config, cert)

    existing = ", ".join(cert.names())
    question = (
        "You have an existing certificate that contains a portion of "
        "the domains you requested (ref: {0}){br}{br}It contains these "
        "names: {1}{br}{br}You requested these names for the new "
        "certificate: {2}.{br}{br}Do you want to expand and replace this existing "
        "certificate with the new certificate?"
    ).format(cert.configfile.filename,
             existing,
             ", ".join(domains),
             br=os.linesep)
    if config.expand or config.renew_by_default or zope.component.getUtility(
            interfaces.IDisplay).yesno(question, "Expand", "Cancel",
                                       cli_flag="--expand",
                                       force_interactive=True):
        return "renew", cert
    display_util.notify(
        "To obtain a new certificate that contains these names without "
        "replacing your existing certificate for {0}, you must use the "
        "--duplicate option.{br}{br}"
        "For example:{br}{br}{1} --duplicate {2}".format(
            existing,
            sys.argv[0], " ".join(sys.argv[1:]),
            br=os.linesep
        ))
    raise errors.Error(USER_CANCELLED)


def _handle_identical_cert_request(config: configuration.NamespaceConfig,
                                   lineage: storage.RenewableCert,
                                   ) -> Tuple[str, Optional[storage.RenewableCert]]:
    """Figure out what to do if a lineage has the same names as a previously obtained one

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :returns: Tuple of (str action, cert_or_None) as per _find_lineage_for_domains_and_certname
              action can be: "newcert" | "renew" | "reinstall"
    :rtype: `tuple` of `str`

    """
    _handle_unexpected_key_type_migration(config, lineage)

    if not lineage.ensure_deployed():
        return "reinstall", lineage
    if renewal.should_renew(config, lineage):
        return "renew", lineage
    if config.reinstall:
        # Set with --reinstall, force an identical certificate to be
        # reinstalled without further prompting.
        return "reinstall", lineage
    question = (
        "You have an existing certificate that has exactly the same "
        "domains or certificate name you requested and isn't close to expiry."
        "{br}(ref: {0}){br}{br}What would you like to do?"
    ).format(lineage.configfile.filename, br=os.linesep)

    if config.verb == "run":
        keep_opt = "Attempt to reinstall this existing certificate"
    elif config.verb == "certonly":
        keep_opt = "Keep the existing certificate for now"
    choices = [keep_opt,
               "Renew & replace the certificate (may be subject to CA rate limits)"]

    display = zope.component.getUtility(interfaces.IDisplay)
    response = display.menu(question, choices,
                            default=0, force_interactive=True)
    if response[0] == display_util.CANCEL:
        # TODO: Add notification related to command-line options for
        #       skipping the menu for this case.
        raise errors.Error(
            "Operation canceled. You may re-run the client.")
    if response[1] == 0:
        return "reinstall", lineage
    elif response[1] == 1:
        return "renew", lineage
    raise AssertionError('This is impossible')


def _find_lineage_for_domains(config, domains):
    """Determine whether there are duplicated names and how to handle
    them (renew, reinstall, newcert, or raising an error to stop
    the client run if the user chooses to cancel the operation when
    prompted).

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param domains: List of domain names
    :type domains: `list` of `str`

    :returns: Two-element tuple containing desired new-certificate behavior as
              a string token ("reinstall", "renew", or "newcert"), plus either
              a RenewableCert instance or `None` if renewal shouldn't occur.
    :rtype: `tuple` of `str` and :class:`storage.RenewableCert` or `None`

    :raises errors.Error: If the user would like to rerun the client again.

    """
    # Considering the possibility that the requested certificate is
    # related to an existing certificate.  (config.duplicate, which
    # is set with --duplicate, skips all of this logic and forces any
    # kind of certificate to be obtained with renewal = False.)
    if config.duplicate:
        return "newcert", None
    # TODO: Also address superset case
    ident_names_cert, subset_names_cert = cert_manager.find_duplicative_certs(config, domains)
    # XXX ^ schoen is not sure whether that correctly reads the systemwide
    # configuration file.
    if ident_names_cert is None and subset_names_cert is None:
        return "newcert", None

    if ident_names_cert is not None:
        return _handle_identical_cert_request(config, ident_names_cert)
    elif subset_names_cert is not None:
        return _handle_subset_cert_request(config, domains, subset_names_cert)
    return None, None


def _find_cert(config, domains, certname):
    """Finds an existing certificate object given domains and/or a certificate name.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param domains: List of domain names
    :type domains: `list` of `str`

    :param certname: Name of certificate
    :type certname: str

    :returns: Two-element tuple of a boolean that indicates if this function should be
              followed by a call to fetch a certificate from the server, and either a
              RenewableCert instance or None.
    :rtype: `tuple` of `bool` and :class:`storage.RenewableCert` or `None`

    """
    action, lineage = _find_lineage_for_domains_and_certname(config, domains, certname)
    if action == "reinstall":
        logger.info("Keeping the existing certificate")
    return (action != "reinstall"), lineage


def _find_lineage_for_domains_and_certname(config: configuration.NamespaceConfig,
                                           domains: List[str],
                                           certname: str
                                           ) -> Tuple[str, Optional[storage.RenewableCert]]:
    """Find appropriate lineage based on given domains and/or certname.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param domains: List of domain names
    :type domains: `list` of `str`

    :param certname: Name of certificate
    :type certname: str

    :returns: Two-element tuple containing desired new-certificate behavior as
              a string token ("reinstall", "renew", or "newcert"), plus either
              a RenewableCert instance or None if renewal should not occur.

    :rtype: `tuple` of `str` and :class:`storage.RenewableCert` or `None`

    :raises errors.Error: If the user would like to rerun the client again.

    """
    if not certname:
        return _find_lineage_for_domains(config, domains)
    lineage = cert_manager.lineage_for_certname(config, certname)
    if lineage:
        if domains:
            if set(cert_manager.domains_for_certname(config, certname)) != set(domains):
                _handle_unexpected_key_type_migration(config, lineage)
                _ask_user_to_confirm_new_names(config, domains, certname,
                                               lineage.names())  # raises if no
                return "renew", lineage
        # unnecessarily specified domains or no domains specified
        return _handle_identical_cert_request(config, lineage)
    elif domains:
        return "newcert", None
    raise errors.ConfigurationError("No certificate with name {0} found. "
        "Use -d to specify domains, or run certbot certificates to see "
        "possible certificate names.".format(certname))

def _get_added_removed(after, before):
    """Get lists of items removed from `before`
    and a lists of items added to `after`
    """
    added = list(set(after) - set(before))
    removed = list(set(before) - set(after))
    added.sort()
    removed.sort()
    return added, removed

def _format_list(character, strings):
    """Format list with given character
    """
    if not strings:
        formatted = "{br}(None)"
    else:
        formatted = "{br}{ch} " + "{br}{ch} ".join(strings)
    return formatted.format(
        ch=character,
        br=os.linesep
    )

def _ask_user_to_confirm_new_names(config, new_domains, certname, old_domains):
    """Ask user to confirm update cert certname to contain new_domains.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param new_domains: List of new domain names
    :type new_domains: `list` of `str`

    :param certname: Name of certificate
    :type certname: str

    :param old_domains: List of old domain names
    :type old_domains: `list` of `str`

    :returns: None
    :rtype: None

    :raises errors.ConfigurationError: if cert name and domains mismatch

    """
    if config.renew_with_new_domains:
        return

    added, removed = _get_added_removed(new_domains, old_domains)

    msg = ("You are updating certificate {0} to include new domain(s): {1}{br}{br}"
           "You are also removing previously included domain(s): {2}{br}{br}"
           "Did you intend to make this change?".format(
               certname,
               _format_list("+", added),
               _format_list("-", removed),
               br=os.linesep))
    obj = zope.component.getUtility(interfaces.IDisplay)
    if not obj.yesno(msg, "Update certificate", "Cancel", default=True):
        raise errors.ConfigurationError("Specified mismatched certificate name and domains.")


def _find_domains_or_certname(config, installer, question=None):
    """Retrieve domains and certname from config or user input.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :param `str` question: Overriding default question to ask the user if asked
        to choose from domain names.

    :returns: Two-part tuple of domains and certname
    :rtype: `tuple` of list of `str` and `str`

    :raises errors.Error: Usage message, if parameters are not used correctly

    """
    domains = None
    certname = config.certname
    # first, try to get domains from the config
    if config.domains:
        domains = config.domains
    # if we can't do that but we have a certname, get the domains
    # with that certname
    elif certname:
        domains = cert_manager.domains_for_certname(config, certname)

    # that certname might not have existed, or there was a problem.
    # try to get domains from the user.
    if not domains:
        domains = display_ops.choose_names(installer, question)

    if not domains and not certname:
        raise errors.Error("Please specify --domains, or --installer that "
                           "will help in domain names autodiscovery, or "
                           "--cert-name for an existing certificate name.")

    return domains, certname


def _report_next_steps(config: interfaces.IConfig, installer_err: Optional[errors.Error],
                       lineage: Optional[storage.RenewableCert],
                       new_or_renewed_cert: bool = True) -> None:
    """Displays post-run/certonly advice to the user about renewal and installation.

    The output varies by runtime configuration and any errors encountered during installation.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param installer_err: The installer/enhancement error encountered, if any.
    :type error: Optional[errors.Error]

    :param lineage: The resulting certificate lineage from the issuance, if any.
    :type lineage: Optional[storage.RenewableCert]

    :param bool new_or_renewed_cert: Whether the verb execution resulted in a certificate
                                     being saved (created or renewed).

    """
    steps: List[str] = []

    # If the installation or enhancement raised an error, show advice on trying again
    if installer_err:
        steps.append(
            "The certificate was saved, but could not be installed (installer: "
            f"{config.installer}). After fixing the error shown below, try installing it again "
            f"by running:\n  {cli.cli_command} install --cert-name "
            f"{_cert_name_from_config_or_lineage(config, lineage)}"
        )

    # If a certificate was obtained or renewed, show applicable renewal advice
    if new_or_renewed_cert:
        if config.csr:
            steps.append(
                "Certificates created using --csr will not be renewed automatically by Certbot. "
                "You will need to renew the certificate before it expires, by running the same "
                "Certbot command again.")
        elif not config.preconfigured_renewal:
            steps.append(
                "The certificate will need to be renewed before it expires. Certbot can "
                "automatically renew the certificate in the background, but you may need "
                "to take steps to enable that functionality. "
                "See https://certbot.org/renewal-setup for instructions.")

    if not steps:
        return

    # TODO: refactor ANSI escapes during https://github.com/certbot/certbot/issues/8848
    (bold_on, bold_off) = [c if sys.stdout.isatty() and not config.quiet else '' \
                           for c in (util.ANSI_SGR_BOLD, util.ANSI_SGR_RESET)]

    print(bold_on, '\n', 'NEXT STEPS:', bold_off, sep='')
    for step in steps:
        display_util.notify(f"- {step}")

    # If there was an installer error, segregate the error output with a trailing newline
    if installer_err:
        print()


def _report_new_cert(config, cert_path, fullchain_path, key_path=None):
    # type: (interfaces.IConfig, Optional[str], Optional[str], Optional[str]) -> None
    """Reports the creation of a new certificate to the user.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param cert_path: path to certificate
    :type cert_path: str

    :param fullchain_path: path to full chain
    :type fullchain_path: str

    :param key_path: path to private key, if available
    :type key_path: str

    :returns: `None`
    :rtype: None

    """
    if config.dry_run:
        display_util.notify("The dry run was successful.")
        return

    assert cert_path and fullchain_path, "No certificates saved to report."

    display_util.notify(
        ("\nSuccessfully received certificate.\n"
        "Certificate is saved at: {cert_path}\n{key_msg}"
        "This certificate expires on {expiry}.\n"
        "These files will be updated when the certificate renews.{renewal_msg}{nl}").format(
            cert_path=fullchain_path,
            expiry=crypto_util.notAfter(cert_path).date(),
            key_msg="Key is saved at:         {}\n".format(key_path) if key_path else "",
            renewal_msg="\nCertbot has set up a scheduled task to automatically renew this "
                        "certificate in the background." if config.preconfigured_renewal else "",
            nl="\n" if config.verb == "run" else "" # Normalize spacing across verbs
        )
    )


def _csr_report_new_cert(config: interfaces.IConfig, cert_path: Optional[str],
                         chain_path: Optional[str], fullchain_path: Optional[str]):
    """ --csr variant of _report_new_cert.

    Until --csr is overhauled (#8332) this is transitional function to report the creation
    of a new certificate using --csr.
    TODO: remove this function and just call _report_new_cert when --csr is overhauled.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param str cert_path: path to cert.pem

    :param str chain_path: path to chain.pem

    :param str fullchain_path: path to fullchain.pem

    """
    if config.dry_run:
        display_util.notify("The dry run was successful.")
        return

    assert cert_path and fullchain_path, "No certificates saved to report."

    expiry = crypto_util.notAfter(cert_path).date()

    display_util.notify(
        ("\nSuccessfully received certificate.\n"
        "Certificate is saved at:            {cert_path}\n"
        "Intermediate CA chain is saved at:  {chain_path}\n"
        "Full certificate chain is saved at: {fullchain_path}\n"
        "This certificate expires on {expiry}.").format(
            cert_path=cert_path, chain_path=chain_path,
            fullchain_path=fullchain_path, expiry=expiry,
        )
    )


def _determine_account(config):
    """Determine which account to use.

    If ``config.account`` is ``None``, it will be updated based on the
    user input. Same for ``config.email``.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :returns: Account and optionally ACME client API (biproduct of new
        registration).
    :rtype: tuple of :class:`certbot._internal.account.Account` and :class:`acme.client.Client`

    :raises errors.Error: If unable to register an account with ACME server

    """
    def _tos_cb(terms_of_service):
        if config.tos:
            return True
        msg = ("Please read the Terms of Service at {0}. You "
               "must agree in order to register with the ACME "
               "server. Do you agree?".format(terms_of_service))
        obj = zope.component.getUtility(interfaces.IDisplay)
        result = obj.yesno(msg, cli_flag="--agree-tos", force_interactive=True)
        if not result:
            raise errors.Error(
                "Registration cannot proceed without accepting "
                "Terms of Service.")
        return None

    account_storage = account.AccountFileStorage(config)
    acme = None

    if config.account is not None:
        acc = account_storage.load(config.account)
    else:
        accounts = account_storage.find_all()
        if len(accounts) > 1:
            acc = display_ops.choose_account(accounts)
        elif len(accounts) == 1:
            acc = accounts[0]
        else:  # no account registered yet
            if config.email is None and not config.register_unsafely_without_email:
                config.email = display_ops.get_email()
            try:
                acc, acme = client.register(
                    config, account_storage, tos_cb=_tos_cb)
                display_util.notify("Account registered.")
            except errors.MissingCommandlineFlag:
                raise
            except errors.Error:
                logger.debug("", exc_info=True)
                raise errors.Error(
                    "Unable to register an account with ACME server")

    config.account = acc.id
    return acc, acme


def _delete_if_appropriate(config):
    """Does the user want to delete their now-revoked certs? If run in non-interactive mode,
    deleting happens automatically.

    :param config: parsed command line arguments
    :type config: interfaces.IConfig

    :returns: `None`
    :rtype: None

    :raises errors.Error: If anything goes wrong, including bad user input, if an overlapping
        archive dir is found for the specified lineage, etc ...
    """
    display = zope.component.getUtility(interfaces.IDisplay)

    attempt_deletion = config.delete_after_revoke
    if attempt_deletion is None:
        msg = ("Would you like to delete the certificate(s) you just revoked, "
               "along with all earlier and later versions of the certificate?")
        attempt_deletion = display.yesno(msg, yes_label="Yes (recommended)", no_label="No",
                force_interactive=True, default=True)

    if not attempt_deletion:
        return

    # config.cert_path must have been set
    # config.certname may have been set
    assert config.cert_path

    if not config.certname:
        config.certname = cert_manager.cert_path_to_lineage(config)

    # don't delete if the archive_dir is used by some other lineage
    archive_dir = storage.full_archive_path(
            configobj.ConfigObj(
                storage.renewal_file_for_certname(config, config.certname),
                encoding='utf-8', default_encoding='utf-8'),
            config, config.certname)
    try:
        cert_manager.match_and_check_overlaps(config, [lambda x: archive_dir],
            lambda x: x.archive_dir, lambda x: x)
    except errors.OverlappingMatchFound:
        logger.warning("Not deleting revoked certificates due to overlapping archive dirs. "
                       "More than one certificate is using %s", archive_dir)
        return
    except Exception as e:
        msg = ('config.default_archive_dir: {0}, config.live_dir: {1}, archive_dir: {2},'
        'original exception: {3}')
        msg = msg.format(config.default_archive_dir, config.live_dir, archive_dir, e)
        raise errors.Error(msg)

    cert_manager.delete(config)


def _init_le_client(config, authenticator, installer):
    """Initialize Let's Encrypt Client

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param authenticator: Acme authentication handler
    :type authenticator: Optional[interfaces.IAuthenticator]
    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :returns: client: Client object
    :rtype: client.Client

    """
    if authenticator is not None:
        # if authenticator was given, then we will need account...
        acc, acme = _determine_account(config)
        logger.debug("Picked account: %r", acc)
        # XXX
        #crypto_util.validate_key_csr(acc.key)
    else:
        acc, acme = None, None

    return client.Client(config, acc, authenticator, installer, acme=acme)


def unregister(config, unused_plugins):
    """Deactivate account on server

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    account_storage = account.AccountFileStorage(config)
    accounts = account_storage.find_all()

    if not accounts:
        return "Could not find existing account to deactivate."
    yesno = zope.component.getUtility(interfaces.IDisplay).yesno
    prompt = ("Are you sure you would like to irrevocably deactivate "
              "your account?")
    wants_deactivate = yesno(prompt, yes_label='Deactivate', no_label='Abort',
                             default=True)

    if not wants_deactivate:
        return "Deactivation aborted."

    acc, acme = _determine_account(config)
    cb_client = client.Client(config, acc, None, None, acme=acme)

    # delete on boulder
    cb_client.acme.deactivate_registration(acc.regr)
    account_files = account.AccountFileStorage(config)
    # delete local account files
    account_files.delete(config.account)

    display_util.notify("Account deactivated.")
    return None


def register(config, unused_plugins):
    """Create accounts on the server.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None` or a string indicating and error
    :rtype: None or str

    """
    # Portion of _determine_account logic to see whether accounts already
    # exist or not.
    account_storage = account.AccountFileStorage(config)
    accounts = account_storage.find_all()

    if accounts:
        # TODO: add a flag to register a duplicate account (this will
        #       also require extending _determine_account's behavior
        #       or else extracting the registration code from there)
        return ("There is an existing account; registration of a "
                "duplicate account with this command is currently "
                "unsupported.")
    # _determine_account will register an account
    _determine_account(config)
    return None


def update_account(config, unused_plugins):
    """Modify accounts on the server.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None` or a string indicating and error
    :rtype: None or str

    """
    # Portion of _determine_account logic to see whether accounts already
    # exist or not.
    account_storage = account.AccountFileStorage(config)
    accounts = account_storage.find_all()

    if not accounts:
        return "Could not find an existing account to update."
    if config.email is None and not config.register_unsafely_without_email:
        config.email = display_ops.get_email(optional=False)

    acc, acme = _determine_account(config)
    cb_client = client.Client(config, acc, None, None, acme=acme)
    # Empty list of contacts in case the user is removing all emails

    acc_contacts: Iterable[str] = ()
    if config.email:
        acc_contacts = ['mailto:' + email for email in config.email.split(',')]
    # We rely on an exception to interrupt this process if it didn't work.
    prev_regr_uri = acc.regr.uri
    acc.regr = cb_client.acme.update_registration(acc.regr.update(
        body=acc.regr.body.update(contact=acc_contacts)))
    # A v1 account being used as a v2 account will result in changing the uri to
    # the v2 uri. Since it's the same object on disk, put it back to the v1 uri
    # so that we can also continue to use the account object with acmev1.
    acc.regr = acc.regr.update(uri=prev_regr_uri)
    account_storage.update_regr(acc, cb_client.acme)

    if not config.email:
        display_util.notify("Any contact information associated "
                            "with this account has been removed.")
    else:
        eff.prepare_subscription(config, acc)
        display_util.notify("Your e-mail address was updated to {0}.".format(config.email))

    return None


def _cert_name_from_config_or_lineage(config: interfaces.IConfig,
                                      lineage: Optional[storage.RenewableCert]) -> Optional[str]:
    if lineage:
        return lineage.lineagename
    elif config.certname:
        return config.certname
    try:
        cert_name = cert_manager.cert_path_to_lineage(config)
        return cert_name
    except errors.Error:
        pass

    return None


def _install_cert(config, le_client, domains, lineage=None):
    """Install a cert

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param le_client: Client object
    :type le_client: client.Client

    :param domains: List of domains
    :type domains: `list` of `str`

    :param lineage: Certificate lineage object. Defaults to `None`
    :type lineage: storage.RenewableCert

    :returns: `None`
    :rtype: None

    """
    path_provider = lineage if lineage else config
    assert path_provider.cert_path is not None

    le_client.deploy_certificate(domains, path_provider.key_path, path_provider.cert_path,
                                 path_provider.chain_path, path_provider.fullchain_path)
    le_client.enhance_config(domains, path_provider.chain_path)


def install(config, plugins):
    """Install a previously obtained cert in a server.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    # XXX: Update for renewer/RenewableCert
    # FIXME: be consistent about whether errors are raised or returned from
    # this function ...

    try:
        installer, _ = plug_sel.choose_configurator_plugins(config, plugins, "install")
    except errors.PluginSelectionError as e:
        return str(e)

    custom_cert = (config.key_path and config.cert_path)
    if not config.certname and not custom_cert:
        certname_question = "Which certificate would you like to install?"
        config.certname = cert_manager.get_certnames(
            config, "install", allow_multiple=False,
            custom_prompt=certname_question)[0]

    if not enhancements.are_supported(config, installer):
        raise errors.NotSupportedError("One ore more of the requested enhancements "
                                       "are not supported by the selected installer")
    # If cert-path is defined, populate missing (ie. not overridden) values.
    # Unfortunately this can't be done in argument parser, as certificate
    # manager needs the access to renewal directory paths
    if config.certname:
        config = _populate_from_certname(config)
    elif enhancements.are_requested(config):
        # Preflight config check
        raise errors.ConfigurationError("One or more of the requested enhancements "
                                        "require --cert-name to be provided")

    if config.key_path and config.cert_path:
        _check_certificate_and_key(config)
        domains, _ = _find_domains_or_certname(config, installer)
        le_client = _init_le_client(config, authenticator=None, installer=installer)
        _install_cert(config, le_client, domains)
    else:
        raise errors.ConfigurationError("Path to certificate or key was not defined. "
            "If your certificate is managed by Certbot, please use --cert-name "
            "to define which certificate you would like to install.")

    if enhancements.are_requested(config):
        # In the case where we don't have certname, we have errored out already
        lineage = cert_manager.lineage_for_certname(config, config.certname)
        enhancements.enable(lineage, domains, installer, config)

    return None

def _populate_from_certname(config):
    """Helper function for install to populate missing config values from lineage
    defined by --cert-name."""

    lineage = cert_manager.lineage_for_certname(config, config.certname)
    if not lineage:
        return config
    if not config.key_path:
        config.namespace.key_path = lineage.key_path
    if not config.cert_path:
        config.namespace.cert_path = lineage.cert_path
    if not config.chain_path:
        config.namespace.chain_path = lineage.chain_path
    if not config.fullchain_path:
        config.namespace.fullchain_path = lineage.fullchain_path
    return config

def _check_certificate_and_key(config):
    if not os.path.isfile(filesystem.realpath(config.cert_path)):
        raise errors.ConfigurationError("Error while reading certificate from path "
                                        "{0}".format(config.cert_path))
    if not os.path.isfile(filesystem.realpath(config.key_path)):
        raise errors.ConfigurationError("Error while reading private key from path "
                                        "{0}".format(config.key_path))
def plugins_cmd(config, plugins):
    """List server software plugins.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    logger.debug("Expected interfaces: %s", config.ifaces)

    ifaces = [] if config.ifaces is None else config.ifaces
    filtered = plugins.visible().ifaces(ifaces)
    logger.debug("Filtered plugins: %r", filtered)

    notify = functools.partial(zope.component.getUtility(
        interfaces.IDisplay).notification, pause=False)
    if not config.init and not config.prepare:
        notify(str(filtered))
        return

    filtered.init(config)
    verified = filtered.verify(ifaces)
    logger.debug("Verified plugins: %r", verified)

    if not config.prepare:
        notify(str(verified))
        return

    verified.prepare()
    available = verified.available()
    logger.debug("Prepared plugins: %s", available)
    notify(str(available))


def enhance(config, plugins):
    """Add security enhancements to existing configuration

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    supported_enhancements = ["hsts", "redirect", "uir", "staple"]
    # Check that at least one enhancement was requested on command line
    oldstyle_enh = any(getattr(config, enh) for enh in supported_enhancements)
    if not enhancements.are_requested(config) and not oldstyle_enh:
        msg = ("Please specify one or more enhancement types to configure. To list "
               "the available enhancement types, run:\n\n%s --help enhance\n")
        logger.error(msg, sys.argv[0])
        raise errors.MisconfigurationError("No enhancements requested, exiting.")

    try:
        installer, _ = plug_sel.choose_configurator_plugins(config, plugins, "enhance")
    except errors.PluginSelectionError as e:
        return str(e)

    if not enhancements.are_supported(config, installer):
        raise errors.NotSupportedError("One ore more of the requested enhancements "
                                       "are not supported by the selected installer")

    certname_question = ("Which certificate would you like to use to enhance "
                         "your configuration?")
    config.certname = cert_manager.get_certnames(
        config, "enhance", allow_multiple=False,
        custom_prompt=certname_question)[0]
    cert_domains = cert_manager.domains_for_certname(config, config.certname)
    if config.noninteractive_mode:
        domains = cert_domains
    else:
        domain_question = ("Which domain names would you like to enable the "
                           "selected enhancements for?")
        domains = display_ops.choose_values(cert_domains, domain_question)
        if not domains:
            raise errors.Error("User cancelled the domain selection. No domains "
                               "defined, exiting.")

    lineage = cert_manager.lineage_for_certname(config, config.certname)
    if not config.chain_path:
        config.chain_path = lineage.chain_path
    if oldstyle_enh:
        le_client = _init_le_client(config, authenticator=None, installer=installer)
        le_client.enhance_config(domains, config.chain_path, redirect_default=False)
    if enhancements.are_requested(config):
        enhancements.enable(lineage, domains, installer, config)

    return None


def rollback(config, plugins):
    """Rollback server configuration changes made during install.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    client.rollback(config.installer, config.checkpoints, config, plugins)

def update_symlinks(config, unused_plugins):
    """Update the certificate file family symlinks

    Use the information in the config file to make symlinks point to
    the correct archive directory.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    cert_manager.update_live_symlinks(config)

def rename(config, unused_plugins):
    """Rename a certificate

    Use the information in the config file to rename an existing
    lineage.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    cert_manager.rename_lineage(config)

def delete(config, unused_plugins):
    """Delete a certificate

    Use the information in the config file to delete an existing
    lineage.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    cert_manager.delete(config)


def certificates(config, unused_plugins):
    """Display information about certs configured with Certbot

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    cert_manager.certificates(config)


def revoke(config, unused_plugins: plugins_disco.PluginsRegistry) -> Optional[str]:
    """Revoke a previously obtained certificate.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None` or string indicating error in case of error
    :rtype: None or str

    """
    # For user-agent construction
    config.installer = config.authenticator = None

    if config.cert_path is None and config.certname:
        # When revoking via --cert-name, take the cert path and server from renewalparams
        lineage = storage.RenewableCert(
            storage.renewal_file_for_certname(config, config.certname), config)
        config.cert_path = lineage.cert_path
        # --server takes priority over lineage.server
        if lineage.server and not cli.set_by_cli("server"):
            config.server = lineage.server
    elif not config.cert_path or (config.cert_path and config.certname):
        # intentionally not supporting --cert-path & --cert-name together,
        # to avoid dealing with mismatched values
        raise errors.Error("Error! Exactly one of --cert-path or --cert-name must be specified!")

    if config.key_path is not None:  # revocation by cert key
        logger.debug("Revoking %s using certificate key %s",
                     config.cert_path, config.key_path)
        crypto_util.verify_cert_matches_priv_key(config.cert_path, config.key_path)
        with open(config.key_path, 'rb') as f:
            key = jose.JWK.load(f.read())
        acme = client.acme_from_config_key(config, key)
    else:  # revocation by account key
        logger.debug("Revoking %s using Account Key", config.cert_path)
        acc, _ = _determine_account(config)
        acme = client.acme_from_config_key(config, acc.key, acc.regr)

    with open(config.cert_path, 'rb') as f:
        cert = crypto_util.pyopenssl_load_certificate(f.read())[0]
    logger.debug("Reason code for revocation: %s", config.reason)
    try:
        acme.revoke(jose.ComparableX509(cert), config.reason)
        _delete_if_appropriate(config)
    except acme_errors.ClientError as e:
        return str(e)

    display_ops.success_revocation(config.cert_path)
    return None


def run(config, plugins):
    """Obtain a certificate and install.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    # TODO: Make run as close to auth + install as possible
    # Possible difficulties: config.csr was hacked into auth
    try:
        installer, authenticator = plug_sel.choose_configurator_plugins(config, plugins, "run")
    except errors.PluginSelectionError as e:
        return str(e)

    # Preflight check for enhancement support by the selected installer
    if not enhancements.are_supported(config, installer):
        raise errors.NotSupportedError("One ore more of the requested enhancements "
                                       "are not supported by the selected installer")

    # TODO: Handle errors from _init_le_client?
    le_client = _init_le_client(config, authenticator, installer)

    domains, certname = _find_domains_or_certname(config, installer)
    should_get_cert, lineage = _find_cert(config, domains, certname)

    new_lineage = lineage
    if should_get_cert:
        new_lineage = _get_and_save_cert(le_client, config, domains,
            certname, lineage)

    cert_path = new_lineage.cert_path if new_lineage else None
    fullchain_path = new_lineage.fullchain_path if new_lineage else None
    key_path = new_lineage.key_path if new_lineage else None

    if should_get_cert:
        _report_new_cert(config, cert_path, fullchain_path, key_path)

    # The installer error, if any, is being stored as a value here, in order to first print
    # relevant advice in a nice way, before re-raising the error for normal processing.
    installer_err: Optional[errors.Error] = None
    try:
        _install_cert(config, le_client, domains, new_lineage)

        if enhancements.are_requested(config) and new_lineage:
            enhancements.enable(new_lineage, domains, installer, config)

        if lineage is None or not should_get_cert:
            display_ops.success_installation(domains)
        else:
            display_ops.success_renewal(domains)
    except errors.Error as e:
        installer_err = e
    finally:
        _report_next_steps(config, installer_err, new_lineage,
                           new_or_renewed_cert=should_get_cert)
        # If the installer did fail, re-raise the error to bail out
        if installer_err:
            raise installer_err

    _suggest_donation_if_appropriate(config)
    eff.handle_subscription(config, le_client.account)
    return None


def _csr_get_and_save_cert(config, le_client):
    # type: (interfaces.IConfig, client.Client) -> Tuple[Optional[str], Optional[str], Optional[str]] # pylint: disable=line-too-long
    """Obtain a cert using a user-supplied CSR

    This works differently in the CSR case (for now) because we don't
    have the privkey, and therefore can't construct the files for a lineage.
    So we just save the cert & chain to disk :/

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param client: Client object
    :type client: client.Client

    :returns: `cert_path`, `chain_path` and `fullchain_path` as absolute
              paths to the actual files, or None for each if it's a dry-run.
    :rtype: `tuple` of `str`

    """
    csr, _ = config.actual_csr
    csr_names = crypto_util.get_names_from_req(csr.data)
    display_util.notify(
        "{action} for {domains}".format(
            action="Simulating a certificate request" if config.dry_run else
                    "Requesting a certificate",
            domains=display_util.summarize_domain_list(csr_names)
        )
    )
    cert, chain = le_client.obtain_certificate_from_csr(csr)
    if config.dry_run:
        logger.debug(
            "Dry run: skipping saving certificate to %s", config.cert_path)
        return None, None, None
    cert_path, chain_path, fullchain_path = le_client.save_certificate(
        cert, chain, os.path.normpath(config.cert_path),
        os.path.normpath(config.chain_path), os.path.normpath(config.fullchain_path))
    return cert_path, chain_path, fullchain_path


def renew_cert(config, plugins, lineage):
    """Renew & save an existing cert. Do not install it.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :returns: `None`
    :rtype: None

    :raises errors.PluginSelectionError: MissingCommandlineFlag if supplied parameters do not pass

    """
    # installers are used in auth mode to determine domain names
    installer, auth = plug_sel.choose_configurator_plugins(config, plugins, "certonly")
    le_client = _init_le_client(config, auth, installer)

    renewed_lineage = _get_and_save_cert(le_client, config, lineage=lineage)

    if installer and not config.dry_run:
        # In case of a renewal, reload server to pick up new certificate.
        updater.run_renewal_deployer(config, renewed_lineage, installer)
        display_util.notify(f"Reloading {config.installer} server after certificate renewal")
        installer.restart() # type: ignore


def certonly(config, plugins):
    """Authenticate & obtain cert, but do not install it.

    This implements the 'certonly' subcommand.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    :raises errors.Error: If specified plugin could not be used

    """
    # SETUP: Select plugins and construct a client instance
    # installers are used in auth mode to determine domain names
    installer, auth = plug_sel.choose_configurator_plugins(config, plugins, "certonly")

    le_client = _init_le_client(config, auth, installer)

    if config.csr:
        cert_path, chain_path, fullchain_path = _csr_get_and_save_cert(config, le_client)
        _csr_report_new_cert(config, cert_path, chain_path, fullchain_path)
        _report_next_steps(config, None, None)
        _suggest_donation_if_appropriate(config)
        eff.handle_subscription(config, le_client.account)
        return

    domains, certname = _find_domains_or_certname(config, installer)
    should_get_cert, lineage = _find_cert(config, domains, certname)

    if not should_get_cert:
        notify = zope.component.getUtility(interfaces.IDisplay).notification
        notify("Certificate not yet due for renewal; no action taken.", pause=False)
        return

    lineage = _get_and_save_cert(le_client, config, domains, certname, lineage)

    cert_path = lineage.cert_path if lineage else None
    fullchain_path = lineage.fullchain_path if lineage else None
    key_path = lineage.key_path if lineage else None
    _report_new_cert(config, cert_path, fullchain_path, key_path)
    _report_next_steps(config, None, lineage, new_or_renewed_cert=should_get_cert)
    _suggest_donation_if_appropriate(config)
    eff.handle_subscription(config, le_client.account)


def renew(config, unused_plugins):
    """Renew previously-obtained certificates.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param unused_plugins: List of plugins (deprecated)
    :type unused_plugins: plugins_disco.PluginsRegistry

    :returns: `None`
    :rtype: None

    """
    try:
        renewal.handle_renewal_request(config)
    finally:
        hooks.run_saved_post_hooks()


def make_or_verify_needed_dirs(config):
    """Create or verify existence of config, work, and hook directories.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :returns: `None`
    :rtype: None

    """
    util.set_up_core_dir(config.config_dir, constants.CONFIG_DIRS_MODE, config.strict_permissions)
    util.set_up_core_dir(config.work_dir, constants.CONFIG_DIRS_MODE, config.strict_permissions)

    hook_dirs = (config.renewal_pre_hooks_dir,
                 config.renewal_deploy_hooks_dir,
                 config.renewal_post_hooks_dir,)
    for hook_dir in hook_dirs:
        util.make_or_verify_dir(hook_dir, strict=config.strict_permissions)


@contextmanager
def make_displayer(config: configuration.NamespaceConfig
                   ) -> Generator[Union[display_util.NoninteractiveDisplay,
                                        display_util.FileDisplay], None, None]:
    """Creates a display object appropriate to the flags in the supplied config.

    :param config: Configuration object

    :returns: Display object implementing :class:`certbot.interfaces.IDisplay`

    """
    displayer: Union[None, display_util.NoninteractiveDisplay,
                     display_util.FileDisplay] = None
    devnull: Optional[IO] = None

    if config.quiet:
        config.noninteractive_mode = True
        devnull = open(os.devnull, "w")  # pylint: disable=consider-using-with
        displayer = display_util.NoninteractiveDisplay(devnull)
    elif config.noninteractive_mode:
        displayer = display_util.NoninteractiveDisplay(sys.stdout)
    else:
        displayer = display_util.FileDisplay(
            sys.stdout, config.force_interactive)

    try:
        yield displayer
    finally:
        if devnull:
            devnull.close()


def main(cli_args=None):
    """Run Certbot.

    :param cli_args: command line to Certbot, defaults to ``sys.argv[1:]``
    :type cli_args: `list` of `str`

    :returns: value for `sys.exit` about the exit status of Certbot
    :rtype: `str` or `int` or `None`

    """
    if not cli_args:
        cli_args = sys.argv[1:]

    log.pre_arg_parse_setup()

    if os.environ.get('CERTBOT_SNAPPED') == 'True':
        cli_args = snap_config.prepare_env(cli_args)

    plugins = plugins_disco.PluginsRegistry.find_all()
    logger.debug("certbot version: %s", certbot.__version__)
    logger.debug("Location of certbot entry point: %s", sys.argv[0])
    # do not log `config`, as it contains sensitive data (e.g. revoke --key)!
    logger.debug("Arguments: %r", cli_args)
    logger.debug("Discovered plugins: %r", plugins)

    # Some releases of Windows require escape sequences to be enable explicitly
    misc.prepare_virtual_console()

    # note: arg parser internally handles --help (and exits afterwards)
    args = cli.prepare_and_parse_args(plugins, cli_args)
    config = configuration.NamespaceConfig(args)

    # This call is done only for retro-compatibility purposes.
    # TODO: Remove this call once zope dependencies are removed from Certbot.
    zope.component.provideUtility(config)

    # On windows, shell without administrative right cannot create symlinks required by certbot.
    # So we check the rights before continuing.
    misc.raise_for_non_administrative_windows_rights()

    try:
        log.post_arg_parse_setup(config)
        make_or_verify_needed_dirs(config)
    except errors.Error:
        # Let plugins_cmd be run as un-privileged user.
        if config.func != plugins_cmd:  # pylint: disable=comparison-with-callable
            raise

    # Reporter
    report = reporter.Reporter(config)
    zope.component.provideUtility(report)
    util.atexit_register(report.print_messages)

    with make_displayer(config) as displayer:
        zope.component.provideUtility(displayer)

        return config.func(config, plugins)
