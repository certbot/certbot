"""Certbot main entry point."""
from __future__ import print_function
import atexit
import functools
import logging.handlers
import os
import sys
import time
import traceback

import zope.component

from acme import jose
from acme import messages
from acme import errors as acme_errors

import certbot

from certbot import account
from certbot import cert_manager
from certbot import client
from certbot import cli
from certbot import crypto_util
from certbot import colored_logging
from certbot import configuration
from certbot import constants
from certbot import eff
from certbot import errors
from certbot import hooks
from certbot import interfaces
from certbot import util
from certbot import reporter
from certbot import renewal

from certbot.display import util as display_util, ops as display_ops
from certbot.plugins import disco as plugins_disco
from certbot.plugins import selection as plug_sel


_PERM_ERR_FMT = os.linesep.join((
    "The following error was encountered:", "{0}",
    "If running as non-root, set --config-dir, "
    "--work-dir, and --logs-dir to writeable paths."))

USER_CANCELLED = ("User chose to cancel the operation and may "
                  "reinvoke the client.")


logger = logging.getLogger(__name__)


def _suggest_donation_if_appropriate(config, action):
    """Potentially suggest a donation to support Certbot."""
    if config.staging or config.verb == "renew":
        # --dry-run implies --staging
        return
    if action not in ["renew", "newcert"]:
        return
    reporter_util = zope.component.getUtility(interfaces.IReporter)
    msg = ("If you like Certbot, please consider supporting our work by:\n\n"
           "Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate\n"
           "Donating to EFF:                    https://eff.org/donate-le\n\n")
    reporter_util.add_message(msg, reporter_util.LOW_PRIORITY)



def _report_successful_dry_run(config):
    reporter_util = zope.component.getUtility(interfaces.IReporter)
    if config.verb != "renew":
        reporter_util.add_message("The dry run was successful.",
                                  reporter_util.HIGH_PRIORITY, on_crash=False)


def _auth_from_available(le_client, config, domains=None, certname=None, lineage=None):
    """Authenticate and enroll certificate.

    This method finds the relevant lineage, figures out what to do with it,
    then performs that action. Includes calls to hooks, various reports,
    checks, and requests for user input.

    :returns: Tuple of (str action, cert_or_None) as per _find_lineage_for_domains_and_certname
              action can be: "newcert" | "renew" | "reinstall"
    """
    # If lineage is specified, use that one instead of looking around for
    # a matching one.
    if lineage is None:
        # This will find a relevant matching lineage that exists
        action, lineage = _find_lineage_for_domains_and_certname(config, domains, certname)
    else:
        # Renewal, where we already know the specific lineage we're
        # interested in
        action = "renew"

    if action == "reinstall":
        # The lineage already exists; allow the caller to try installing
        # it without getting a new certificate at all.
        logger.info("Keeping the existing certificate")
        return "reinstall", lineage

    hooks.pre_hook(config)
    try:
        if action == "renew":
            logger.info("Renewing an existing certificate")
            renewal.renew_cert(config, domains, le_client, lineage)
        elif action == "newcert":
            # TREAT AS NEW REQUEST
            logger.info("Obtaining a new certificate")
            lineage = le_client.obtain_and_enroll_certificate(domains, certname)
            if lineage is False:
                raise errors.Error("Certificate could not be obtained")
    finally:
        hooks.post_hook(config)

    if not config.dry_run and not config.verb == "renew":
        _report_new_cert(config, lineage.cert, lineage.fullchain)

    return action, lineage


def _handle_subset_cert_request(config, domains, cert):
    """Figure out what to do if a previous cert had a subset of the names now requested

    :param storage.RenewableCert cert:

    :returns: Tuple of (str action, cert_or_None) as per _find_lineage_for_domains_and_certname
              action can be: "newcert" | "renew" | "reinstall"
    :rtype: tuple

    """
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
    else:
        reporter_util = zope.component.getUtility(interfaces.IReporter)
        reporter_util.add_message(
            "To obtain a new certificate that contains these names without "
            "replacing your existing certificate for {0}, you must use the "
            "--duplicate option.{br}{br}"
            "For example:{br}{br}{1} --duplicate {2}".format(
                existing,
                sys.argv[0], " ".join(sys.argv[1:]),
                br=os.linesep
            ),
            reporter_util.HIGH_PRIORITY)
        raise errors.Error(USER_CANCELLED)


def _handle_identical_cert_request(config, lineage):
    """Figure out what to do if a lineage has the same names as a previously obtained one

    :param storage.RenewableCert lineage:

    :returns: Tuple of (str action, cert_or_None) as per _find_lineage_for_domains_and_certname
              action can be: "newcert" | "renew" | "reinstall"
    :rtype: tuple

    """
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
               "Renew & replace the cert (limit ~5 per 7 days)"]

    display = zope.component.getUtility(interfaces.IDisplay)
    response = display.menu(question, choices, "OK", "Cancel",
                            default=0, force_interactive=True)
    if response[0] == display_util.CANCEL:
        # TODO: Add notification related to command-line options for
        #       skipping the menu for this case.
        raise errors.Error(
            "User chose to cancel the operation and may "
            "reinvoke the client.")
    elif response[1] == 0:
        return "reinstall", lineage
    elif response[1] == 1:
        return "renew", lineage
    else:
        assert False, "This is impossible"

def _find_lineage_for_domains(config, domains):
    """Determine whether there are duplicated names and how to handle
    them (renew, reinstall, newcert, or raising an error to stop
    the client run if the user chooses to cancel the operation when
    prompted).

    :returns: Two-element tuple containing desired new-certificate behavior as
              a string token ("reinstall", "renew", or "newcert"), plus either
              a RenewableCert instance or None if renewal shouldn't occur.

    :raises .Error: If the user would like to rerun the client again.

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

def _find_lineage_for_domains_and_certname(config, domains, certname):
    """Find appropriate lineage based on given domains and/or certname.

    :returns: Two-element tuple containing desired new-certificate behavior as
              a string token ("reinstall", "renew", or "newcert"), plus either
              a RenewableCert instance or None if renewal shouldn't occur.

    :raises .Error: If the user would like to rerun the client again.

    """
    if not certname:
        return _find_lineage_for_domains(config, domains)
    else:
        lineage = cert_manager.lineage_for_certname(config, certname)
        if lineage:
            if domains:
                if set(cert_manager.domains_for_certname(config, certname)) != set(domains):
                    _ask_user_to_confirm_new_names(config, domains, certname,
                        lineage.names()) # raises if no
                    return "renew", lineage
            # unnecessarily specified domains or no domains specified
            return _handle_identical_cert_request(config, lineage)
        else:
            if domains:
                return "newcert", None
            else:
                raise errors.ConfigurationError("No certificate with name {0} found. "
                    "Use -d to specify domains, or run certbot --certificates to see "
                    "possible certificate names.".format(certname))

def _ask_user_to_confirm_new_names(config, new_domains, certname, old_domains):
    """Ask user to confirm update cert certname to contain new_domains.
    """
    if config.renew_with_new_domains:
        return
    msg = ("Confirm that you intend to update certificate {0} "
           "to include domains {1}. Note that it previously "
           "contained domains {2}.".format(
               certname,
               new_domains,
               old_domains))
    obj = zope.component.getUtility(interfaces.IDisplay)
    if not obj.yesno(msg, "Update cert", "Cancel", default=True):
        raise errors.ConfigurationError("Specified mismatched cert name and domains.")

def _find_domains_or_certname(config, installer):
    """Retrieve domains and certname from config or user input.
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
        domains = display_ops.choose_names(installer)

    if not domains and not certname:
        raise errors.Error("Please specify --domains, or --installer that "
                           "will help in domain names autodiscovery, or "
                           "--cert-name for an existing certificate name.")

    return domains, certname


def _report_new_cert(config, cert_path, fullchain_path):
    """Reports the creation of a new certificate to the user.

    :param str cert_path: path to cert
    :param str fullchain_path: path to full chain

    """
    expiry = crypto_util.notAfter(cert_path).date()
    reporter_util = zope.component.getUtility(interfaces.IReporter)
    if fullchain_path:
        # Print the path to fullchain.pem because that's what modern webservers
        # (Nginx and Apache2.4) will want.
        and_chain = "and chain have"
        path = fullchain_path
    else:
        # Unless we're in .csr mode and there really isn't one
        and_chain = "has "
        path = cert_path

    verbswitch = ' with the "certonly" option' if config.verb == "run" else ""
    # XXX Perhaps one day we could detect the presence of known old webservers
    # and say something more informative here.
    msg = ('Congratulations! Your certificate {0} been saved at {1}.'
           ' Your cert will expire on {2}. To obtain a new or tweaked version of this '
           'certificate in the future, simply run {3} again{4}. '
           'To non-interactively renew *all* of your certificates, run "{3} renew"'
           .format(and_chain, path, expiry, cli.cli_command, verbswitch))
    reporter_util.add_message(msg, reporter_util.MEDIUM_PRIORITY)


def _determine_account(config):
    """Determine which account to use.

    In order to make the renewer (configuration de/serialization) happy,
    if ``config.account`` is ``None``, it will be updated based on the
    user input. Same for ``config.email``.

    :param argparse.Namespace config: CLI arguments
    :param certbot.interface.IConfig config: Configuration object
    :param .AccountStorage account_storage: Account storage.

    :returns: Account and optionally ACME client API (biproduct of new
        registration).
    :rtype: `tuple` of `certbot.account.Account` and
        `acme.client.Client`

    """
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
                config.namespace.email = display_ops.get_email()

            def _tos_cb(regr):
                if config.tos:
                    return True
                msg = ("Please read the Terms of Service at {0}. You "
                       "must agree in order to register with the ACME "
                       "server at {1}".format(
                           regr.terms_of_service, config.server))
                obj = zope.component.getUtility(interfaces.IDisplay)
                return obj.yesno(msg, "Agree", "Cancel",
                                 cli_flag="--agree-tos", force_interactive=True)

            try:
                acc, acme = client.register(
                    config, account_storage, tos_cb=_tos_cb)
            except errors.MissingCommandlineFlag:
                raise
            except errors.Error as error:
                logger.debug(error, exc_info=True)
                raise errors.Error(
                    "Unable to register an account with ACME server")

    config.namespace.account = acc.id
    return acc, acme


def _init_le_client(config, authenticator, installer):
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
    """Deactivate account on server"""
    account_storage = account.AccountFileStorage(config)
    accounts = account_storage.find_all()
    reporter_util = zope.component.getUtility(interfaces.IReporter)

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
    acme_client = client.Client(config, acc, None, None, acme=acme)

    # delete on boulder
    acme_client.acme.deactivate_registration(acc.regr)
    account_files = account.AccountFileStorage(config)
    # delete local account files
    account_files.delete(config.account)

    reporter_util.add_message("Account deactivated.", reporter_util.MEDIUM_PRIORITY)


def register(config, unused_plugins):
    """Create or modify accounts on the server."""

    # Portion of _determine_account logic to see whether accounts already
    # exist or not.
    account_storage = account.AccountFileStorage(config)
    accounts = account_storage.find_all()
    reporter_util = zope.component.getUtility(interfaces.IReporter)
    add_msg = lambda m: reporter_util.add_message(m, reporter_util.MEDIUM_PRIORITY)

    # registering a new account
    if not config.update_registration:
        if len(accounts) > 0:
            # TODO: add a flag to register a duplicate account (this will
            #       also require extending _determine_account's behavior
            #       or else extracting the registration code from there)
            return ("There is an existing account; registration of a "
                    "duplicate account with this command is currently "
                    "unsupported.")
        # _determine_account will register an account
        _determine_account(config)
        return

    # --update-registration
    if len(accounts) == 0:
        return "Could not find an existing account to update."
    if config.email is None:
        if config.register_unsafely_without_email:
            return ("--register-unsafely-without-email provided, however, a "
                    "new e-mail address must\ncurrently be provided when "
                    "updating a registration.")
        config.namespace.email = display_ops.get_email(optional=False)

    acc, acme = _determine_account(config)
    acme_client = client.Client(config, acc, None, None, acme=acme)
    # We rely on an exception to interrupt this process if it didn't work.
    acc.regr = acme_client.acme.update_registration(acc.regr.update(
        body=acc.regr.body.update(contact=('mailto:' + config.email,))))
    account_storage.save_regr(acc)
    eff.handle_subscription(config)
    add_msg("Your e-mail address was updated to {0}.".format(config.email))


def install(config, plugins):
    """Install a previously obtained cert in a server."""
    # XXX: Update for renewer/RenewableCert
    # FIXME: be consistent about whether errors are raised or returned from
    # this function ...

    try:
        installer, _ = plug_sel.choose_configurator_plugins(config, plugins, "install")
    except errors.PluginSelectionError as e:
        return e.message

    domains, _ = _find_domains_or_certname(config, installer)
    le_client = _init_le_client(config, authenticator=None, installer=installer)
    assert config.cert_path is not None  # required=True in the subparser
    le_client.deploy_certificate(
        domains, config.key_path, config.cert_path, config.chain_path,
        config.fullchain_path)
    le_client.enhance_config(domains, config.chain_path)


def plugins_cmd(config, plugins):  # TODO: Use IDisplay rather than print
    """List server software plugins."""
    logger.debug("Expected interfaces: %s", config.ifaces)

    ifaces = [] if config.ifaces is None else config.ifaces
    filtered = plugins.visible().ifaces(ifaces)
    logger.debug("Filtered plugins: %r", filtered)

    if not config.init and not config.prepare:
        print(str(filtered))
        return

    filtered.init(config)
    verified = filtered.verify(ifaces)
    logger.debug("Verified plugins: %r", verified)

    if not config.prepare:
        print(str(verified))
        return

    verified.prepare()
    available = verified.available()
    logger.debug("Prepared plugins: %s", available)
    print(str(available))


def rollback(config, plugins):
    """Rollback server configuration changes made during install."""
    client.rollback(config.installer, config.checkpoints, config, plugins)


def config_changes(config, unused_plugins):
    """Show changes made to server config during installation

    View checkpoints and associated configuration changes.

    """
    client.view_config_changes(config, num=config.num)

def update_symlinks(config, unused_plugins):
    """Update the certificate file family symlinks

    Use the information in the config file to make symlinks point to
    the correct archive directory.
    """
    cert_manager.update_live_symlinks(config)

def rename(config, unused_plugins):
    """Rename a certificate

    Use the information in the config file to rename an existing
    lineage.
    """
    cert_manager.rename_lineage(config)

def delete(config, unused_plugins):
    """Delete a certificate

    Use the information in the config file to delete an existing
    lineage.
    """
    cert_manager.delete(config)

def certificates(config, unused_plugins):
    """Display information about certs configured with Certbot
    """
    cert_manager.certificates(config)

def revoke(config, unused_plugins):  # TODO: coop with renewal config
    """Revoke a previously obtained certificate."""
    # For user-agent construction
    config.namespace.installer = config.namespace.authenticator = "None"
    if config.key_path is not None:  # revocation by cert key
        logger.debug("Revoking %s using cert key %s",
                     config.cert_path[0], config.key_path[0])
        key = jose.JWK.load(config.key_path[1])
    else:  # revocation by account key
        logger.debug("Revoking %s using Account Key", config.cert_path[0])
        acc, _ = _determine_account(config)
        key = acc.key
    acme = client.acme_from_config_key(config, key)
    cert = crypto_util.pyopenssl_load_certificate(config.cert_path[1])[0]
    logger.debug("Reason code for revocation: %s", config.reason)

    try:
        acme.revoke(jose.ComparableX509(cert), config.reason)
    except acme_errors.ClientError as e:
        return e.message

    display_ops.success_revocation(config.cert_path[0])


def run(config, plugins):  # pylint: disable=too-many-branches,too-many-locals
    """Obtain a certificate and install."""
    # TODO: Make run as close to auth + install as possible
    # Possible difficulties: config.csr was hacked into auth
    try:
        installer, authenticator = plug_sel.choose_configurator_plugins(config, plugins, "run")
    except errors.PluginSelectionError as e:
        return e.message

    domains, certname = _find_domains_or_certname(config, installer)

    # TODO: Handle errors from _init_le_client?
    le_client = _init_le_client(config, authenticator, installer)

    action, lineage = _auth_from_available(le_client, config, domains, certname)

    le_client.deploy_certificate(
        domains, lineage.privkey, lineage.cert,
        lineage.chain, lineage.fullchain)

    le_client.enhance_config(domains, lineage.chain)

    if action in ("newcert", "reinstall",):
        display_ops.success_installation(domains)
    else:
        display_ops.success_renewal(domains)

    _suggest_donation_if_appropriate(config, action)


def _csr_obtain_cert(config, le_client):
    """Obtain a cert using a user-supplied CSR

    This works differently in the CSR case (for now) because we don't
    have the privkey, and therefore can't construct the files for a lineage.
    So we just save the cert & chain to disk :/
    """
    csr, typ = config.actual_csr
    certr, chain = le_client.obtain_certificate_from_csr(config.domains, csr, typ)
    if config.dry_run:
        logger.debug(
            "Dry run: skipping saving certificate to %s", config.cert_path)
    else:
        cert_path, _, cert_fullchain = le_client.save_certificate(
            certr, chain, config.cert_path, config.chain_path, config.fullchain_path)
        _report_new_cert(config, cert_path, cert_fullchain)

def obtain_cert(config, plugins, lineage=None):
    """Authenticate & obtain cert, but do not install it.

    This implements the 'certonly' subcommand, and is also called from within the
    'renew' command."""

    # SETUP: Select plugins and construct a client instance
    try:
        # installers are used in auth mode to determine domain names
        installer, auth = plug_sel.choose_configurator_plugins(config, plugins, "certonly")
    except errors.PluginSelectionError as e:
        logger.info("Could not choose appropriate plugin: %s", e)
        raise
    le_client = _init_le_client(config, auth, installer)

    # SHOWTIME: Possibly obtain/renew a cert, and set action to renew | newcert | reinstall
    if config.csr is None: # the common case
        domains, certname = _find_domains_or_certname(config, installer)
        action, _ = _auth_from_available(le_client, config, domains, certname, lineage)
    else:
        assert lineage is None, "Did not expect a CSR with a RenewableCert"
        _csr_obtain_cert(config, le_client)
        action = "newcert"

    # POSTPRODUCTION: Cleanup, deployment & reporting
    notify = zope.component.getUtility(interfaces.IDisplay).notification
    if config.dry_run:
        _report_successful_dry_run(config)
    elif config.verb == "renew":
        if installer is None:
            notify("new certificate deployed without reload, fullchain is {0}".format(
                   lineage.fullchain), pause=False)
        else:
            # In case of a renewal, reload server to pick up new certificate.
            # In principle we could have a configuration option to inhibit this
            # from happening.
            installer.restart()
            notify("new certificate deployed with reload of {0} server; fullchain is {1}".format(
                   config.installer, lineage.fullchain), pause=False)
    elif action == "reinstall" and config.verb == "certonly":
        notify("Certificate not yet due for renewal; no action taken.", pause=False)
    _suggest_donation_if_appropriate(config, action)


def renew(config, unused_plugins):
    """Renew previously-obtained certificates."""
    try:
        renewal.handle_renewal_request(config)
    finally:
        hooks.run_saved_post_hooks()


def setup_log_file_handler(config, logfile, fmt):
    """Setup file debug logging."""
    log_file_path = os.path.join(config.logs_dir, logfile)
    try:
        handler = logging.handlers.RotatingFileHandler(
            log_file_path, maxBytes=2 ** 20, backupCount=1000)
    except IOError as error:
        raise errors.Error(_PERM_ERR_FMT.format(error))
    # rotate on each invocation, rollover only possible when maxBytes
    # is nonzero and backupCount is nonzero, so we set maxBytes as big
    # as possible not to overrun in single CLI invocation (1MB).
    handler.doRollover()  # TODO: creates empty letsencrypt.log.1 file
    handler.setLevel(logging.DEBUG)
    handler_formatter = logging.Formatter(fmt=fmt)
    handler_formatter.converter = time.gmtime  # don't use localtime
    handler.setFormatter(handler_formatter)
    return handler, log_file_path


def _cli_log_handler(level, fmt):
    handler = colored_logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt))
    handler.setLevel(level)
    return handler


def setup_logging(config):
    """Sets up logging to logfiles and the terminal.

    :param certbot.interface.IConfig config: Configuration object

    """
    cli_fmt = "%(message)s"
    file_fmt = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
    logfile = "letsencrypt.log"
    if config.quiet:
        level = constants.QUIET_LOGGING_LEVEL
    else:
        level = -config.verbose_count * 10
    file_handler, log_file_path = setup_log_file_handler(
        config, logfile=logfile, fmt=file_fmt)
    cli_handler = _cli_log_handler(level, cli_fmt)

    # TODO: use fileConfig?

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # send all records to handlers
    root_logger.addHandler(cli_handler)
    root_logger.addHandler(file_handler)

    logger.debug("Root logging level set at %d", level)
    logger.info("Saving debug log to %s", log_file_path)


def _handle_exception(exc_type, exc_value, trace, config):
    """Logs exceptions and reports them to the user.

    Config is used to determine how to display exceptions to the user. In
    general, if config.debug is True, then the full exception and traceback is
    shown to the user, otherwise it is suppressed. If config itself is None,
    then the traceback and exception is attempted to be written to a logfile.
    If this is successful, the traceback is suppressed, otherwise it is shown
    to the user. sys.exit is always called with a nonzero status.

    """
    tb_str = "".join(traceback.format_exception(exc_type, exc_value, trace))
    logger.debug("Exiting abnormally:%s%s", os.linesep, tb_str)

    if issubclass(exc_type, Exception) and (config is None or not config.debug):
        if config is None:
            logfile = "certbot.log"
            try:
                with open(logfile, "w") as logfd:
                    traceback.print_exception(
                        exc_type, exc_value, trace, file=logfd)
                assert "--debug" not in sys.argv  # config is None if this explodes
            except:  # pylint: disable=bare-except
                sys.exit(tb_str)
            if "--debug" in sys.argv:
                sys.exit(tb_str)

        if issubclass(exc_type, errors.Error):
            sys.exit(exc_value)
        else:
            # Here we're passing a client or ACME error out to the client at the shell
            # Tell the user a bit about what happened, without overwhelming
            # them with a full traceback
            err = traceback.format_exception_only(exc_type, exc_value)[0]
            # Typical error from the ACME module:
            # acme.messages.Error: urn:ietf:params:acme:error:malformed :: The
            # request message was malformed :: Error creating new registration
            # :: Validation of contact mailto:none@longrandomstring.biz failed:
            # Server failure at resolver
            if (messages.is_acme_error(err) and ":: " in err and
                 config.verbose_count <= cli.flag_default("verbose_count")):
                # prune ACME error code, we have a human description
                _code, _sep, err = err.partition(":: ")
            msg = "An unexpected error occurred:\n" + err + "Please see the "
            if config is None:
                msg += "logfile '{0}' for more details.".format(logfile)
            else:
                msg += "logfiles in {0} for more details.".format(config.logs_dir)
            sys.exit(msg)
    else:
        sys.exit(tb_str)


def make_or_verify_core_dir(directory, mode, uid, strict):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.
    :param bool strict: require directory to be owned by current user

    :raises .errors.Error: if the directory cannot be made or verified

    """
    try:
        util.make_or_verify_dir(directory, mode, uid, strict)
    except OSError as error:
        raise errors.Error(_PERM_ERR_FMT.format(error))

def make_or_verify_needed_dirs(config):
    """Create or verify existence of config, work, or logs directories"""
    make_or_verify_core_dir(config.config_dir, constants.CONFIG_DIRS_MODE,
                            os.geteuid(), config.strict_permissions)
    make_or_verify_core_dir(config.work_dir, constants.CONFIG_DIRS_MODE,
                            os.geteuid(), config.strict_permissions)
    # TODO: logs might contain sensitive data such as contents of the
    # private key! #525
    make_or_verify_core_dir(config.logs_dir, 0o700,
                            os.geteuid(), config.strict_permissions)


def set_displayer(config):
    """Set the displayer"""
    if config.quiet:
        config.noninteractive_mode = True
        displayer = display_util.NoninteractiveDisplay(open(os.devnull, "w"))
    elif config.noninteractive_mode:
        displayer = display_util.NoninteractiveDisplay(sys.stdout)
    else:
        displayer = display_util.FileDisplay(sys.stdout,
                                             config.force_interactive)
    zope.component.provideUtility(displayer)

def _post_logging_setup(config, plugins, cli_args):
    """Perform any setup or configuration tasks that require a logger."""

    # This needs logging, but would otherwise be in HelpfulArgumentParser
    if config.validate_hooks:
        hooks.validate_hooks(config)

    cli.possible_deprecation_warning(config)

    logger.debug("certbot version: %s", certbot.__version__)
    # do not log `config`, as it contains sensitive data (e.g. revoke --key)!
    logger.debug("Arguments: %r", cli_args)
    logger.debug("Discovered plugins: %r", plugins)


def main(cli_args=sys.argv[1:]):
    """Command line argument parsing and main script execution."""
    sys.excepthook = functools.partial(_handle_exception, config=None)
    plugins = plugins_disco.PluginsRegistry.find_all()

    # note: arg parser internally handles --help (and exits afterwards)
    args = cli.prepare_and_parse_args(plugins, cli_args)
    config = configuration.NamespaceConfig(args)
    zope.component.provideUtility(config)

    make_or_verify_needed_dirs(config)

    # Setup logging ASAP, otherwise "No handlers could be found for
    # logger ..." TODO: this should be done before plugins discovery
    setup_logging(config)

    _post_logging_setup(config, plugins, cli_args)

    sys.excepthook = functools.partial(_handle_exception, config=config)

    set_displayer(config)

    # Reporter
    report = reporter.Reporter(config)
    zope.component.provideUtility(report)
    atexit.register(report.atexit_print_messages)

    return config.func(config, plugins)


if __name__ == "__main__":
    err_string = main()
    if err_string:
        logger.warning("Exiting with message %s", err_string)
    sys.exit(err_string)  # pragma: no cover
