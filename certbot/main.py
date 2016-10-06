"""Certbot main entry point."""
from __future__ import print_function
import atexit
import dialog
import functools
import logging.handlers
import os
import sys
import time
import traceback

import zope.component

from acme import jose

import certbot

from certbot import account
from certbot import client
from certbot import cli
from certbot import crypto_util
from certbot import colored_logging
from certbot import configuration
from certbot import constants
from certbot import errors
from certbot import hooks
from certbot import interfaces
from certbot import util
from certbot import log
from certbot import reporter
from certbot import renewal
from certbot import storage

from certbot.display import util as display_util, ops as display_ops
from certbot.plugins import disco as plugins_disco
from certbot.plugins import selection as plug_sel


_PERM_ERR_FMT = os.linesep.join((
    "The following error was encountered:", "{0}",
    "If running as non-root, set --config-dir, "
    "--logs-dir, and --work-dir to writeable paths."))


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


def _auth_from_domains(le_client, config, domains, lineage=None):
    """Authenticate and enroll certificate.

    :returns: Tuple of (str action, cert_or_None) as per _treat_as_renewal
              action can be: "newcert" | "renew" | "reinstall"
    """
    # If lineage is specified, use that one instead of looking around for
    # a matching one.
    if lineage is None:
        # This will find a relevant matching lineage that exists
        action, lineage = _treat_as_renewal(config, domains)
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
            lineage = le_client.obtain_and_enroll_certificate(domains)
            if lineage is False:
                raise errors.Error("Certificate could not be obtained")
    finally:
        hooks.post_hook(config, final=False)

    if not config.dry_run and not config.verb == "renew":
        _report_new_cert(config, lineage.cert, lineage.fullchain)

    return action, lineage


def _handle_subset_cert_request(config, domains, cert):
    """Figure out what to do if a previous cert had a subset of the names now requested

    :param storage.RenewableCert cert:

    :returns: Tuple of (str action, cert_or_None) as per _treat_as_renewal
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
                                       cli_flag="--expand"):
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
        raise errors.Error(
            "User chose to cancel the operation and may "
            "reinvoke the client.")


def _handle_identical_cert_request(config, lineage):
    """Figure out what to do if a lineage has the same names as a previously obtained one

    :param storage.RenewableCert lineage:

    :returns: Tuple of (str action, cert_or_None) as per _treat_as_renewal
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
        "You have an existing certificate that contains exactly the same "
        "domains you requested and isn't close to expiry."
        "{br}(ref: {0}){br}{br}What would you like to do?"
    ).format(lineage.configfile.filename, br=os.linesep)

    if config.verb == "run":
        keep_opt = "Attempt to reinstall this existing certificate"
    elif config.verb == "certonly":
        keep_opt = "Keep the existing certificate for now"
    choices = [keep_opt,
               "Renew & replace the cert (limit ~5 per 7 days)"]

    display = zope.component.getUtility(interfaces.IDisplay)
    response = display.menu(question, choices, "OK", "Cancel", default=0)
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


def _treat_as_renewal(config, domains):
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
    ident_names_cert, subset_names_cert = _find_duplicative_certs(config, domains)
    # XXX ^ schoen is not sure whether that correctly reads the systemwide
    # configuration file.
    if ident_names_cert is None and subset_names_cert is None:
        return "newcert", None

    if ident_names_cert is not None:
        return _handle_identical_cert_request(config, ident_names_cert)
    elif subset_names_cert is not None:
        return _handle_subset_cert_request(config, domains, subset_names_cert)


def _find_duplicative_certs(config, domains):
    """Find existing certs that duplicate the request."""

    identical_names_cert, subset_names_cert = None, None

    cli_config = configuration.RenewerConfiguration(config)
    configs_dir = cli_config.renewal_configs_dir
    # Verify the directory is there
    util.make_or_verify_dir(configs_dir, mode=0o755, uid=os.geteuid())

    for renewal_file in renewal.renewal_conf_files(cli_config):
        try:
            candidate_lineage = storage.RenewableCert(renewal_file, cli_config)
        except (errors.CertStorageError, IOError):
            logger.warning("Renewal conf file %s is broken. Skipping.", renewal_file)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            continue
        # TODO: Handle these differently depending on whether they are
        #       expired or still valid?
        candidate_names = set(candidate_lineage.names())
        if candidate_names == set(domains):
            identical_names_cert = candidate_lineage
        elif candidate_names.issubset(set(domains)):
            # This logic finds and returns the largest subset-names cert
            # in the case where there are several available.
            if subset_names_cert is None:
                subset_names_cert = candidate_lineage
            elif len(candidate_names) > len(subset_names_cert.names()):
                subset_names_cert = candidate_lineage

    return identical_names_cert, subset_names_cert


def _find_domains(config, installer):
    if config.domains:
        domains = config.domains
    else:
        domains = display_ops.choose_names(installer)

    if not domains:
        raise errors.Error("Please specify --domains, or --installer that "
                           "will help in domain names autodiscovery")

    return domains


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
                return obj.yesno(msg, "Agree", "Cancel", cli_flag="--agree-tos")

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


def register(config, unused_plugins):
    """Create or modify accounts on the server."""

    # Portion of _determine_account logic to see whether accounts already
    # exist or not.
    account_storage = account.AccountFileStorage(config)
    accounts = account_storage.find_all()

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
    reporter_util = zope.component.getUtility(interfaces.IReporter)
    msg = "Your e-mail address was updated to {0}.".format(config.email)
    reporter_util.add_message(msg, reporter_util.MEDIUM_PRIORITY)


def install(config, plugins):
    """Install a previously obtained cert in a server."""
    # XXX: Update for renewer/RenewableCert
    # FIXME: be consistent about whether errors are raised or returned from
    # this function ...

    try:
        installer, _ = plug_sel.choose_configurator_plugins(config, plugins, "install")
    except errors.PluginSelectionError as e:
        return e.message

    domains = _find_domains(config, installer)
    le_client = _init_le_client(config, authenticator=None, installer=installer)
    assert config.cert_path is not None  # required=True in the subparser
    le_client.deploy_certificate(
        domains, config.key_path, config.cert_path, config.chain_path,
        config.fullchain_path)
    le_client.enhance_config(domains, config, config.chain_path)


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
    acme.revoke(jose.ComparableX509(cert))


def run(config, plugins):  # pylint: disable=too-many-branches,too-many-locals
    """Obtain a certificate and install."""
    # TODO: Make run as close to auth + install as possible
    # Possible difficulties: config.csr was hacked into auth
    try:
        installer, authenticator = plug_sel.choose_configurator_plugins(config, plugins, "run")
    except errors.PluginSelectionError as e:
        return e.message

    domains = _find_domains(config, installer)

    # TODO: Handle errors from _init_le_client?
    le_client = _init_le_client(config, authenticator, installer)

    action, lineage = _auth_from_domains(le_client, config, domains)

    le_client.deploy_certificate(
        domains, lineage.privkey, lineage.cert,
        lineage.chain, lineage.fullchain)

    le_client.enhance_config(domains, config, lineage.chain)

    if len(lineage.available_versions("cert")) == 1:
        display_ops.success_installation(domains)
    else:
        display_ops.success_renewal(domains, action)

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
        domains = _find_domains(config, installer)
        action, _ = _auth_from_domains(le_client, config, domains, lineage)
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
        renewal.renew_all_lineages(config)
    finally:
        hooks.post_hook(config, final=True)


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


def _cli_log_handler(config, level, fmt):
    if config.text_mode or config.noninteractive_mode or config.verb == "renew":
        handler = colored_logging.StreamHandler()
        handler.setFormatter(logging.Formatter(fmt))
    else:
        handler = log.DialogHandler()
        # dialog box is small, display as less as possible
        handler.setFormatter(logging.Formatter("%(message)s"))
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
    cli_handler = _cli_log_handler(config, level, cli_fmt)

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
    logger.debug(
        "Exiting abnormally:%s%s",
        os.linesep,
        "".join(traceback.format_exception(exc_type, exc_value, trace)))

    if issubclass(exc_type, Exception) and (config is None or not config.debug):
        if config is None:
            logfile = "certbot.log"
            try:
                with open(logfile, "w") as logfd:
                    traceback.print_exception(
                        exc_type, exc_value, trace, file=logfd)
            except:  # pylint: disable=bare-except
                sys.exit("".join(
                    traceback.format_exception(exc_type, exc_value, trace)))

        if issubclass(exc_type, errors.Error):
            sys.exit(exc_value)
        else:
            # Here we're passing a client or ACME error out to the client at the shell
            # Tell the user a bit about what happened, without overwhelming
            # them with a full traceback
            if issubclass(exc_type, dialog.error):
                err = exc_value.complete_message()
            else:
                err = traceback.format_exception_only(exc_type, exc_value)[0]
            # Typical error from the ACME module:
            # acme.messages.Error: urn:acme:error:malformed :: The request message was
            # malformed :: Error creating new registration :: Validation of contact
            # mailto:none@longrandomstring.biz failed: Server failure at resolver
            if (("urn:acme" in err and ":: " in err and
                 config.verbose_count <= cli.flag_default("verbose_count"))):
                # prune ACME error code, we have a human description
                _code, _sep, err = err.partition(":: ")
            msg = "An unexpected error occurred:\n" + err + "Please see the "
            if config is None:
                msg += "logfile '{0}' for more details.".format(logfile)
            else:
                msg += "logfiles in {0} for more details.".format(config.logs_dir)
            sys.exit(msg)
    else:
        sys.exit("".join(
            traceback.format_exception(exc_type, exc_value, trace)))


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


def main(cli_args=sys.argv[1:]):
    """Command line argument parsing and main script execution."""
    sys.excepthook = functools.partial(_handle_exception, config=None)
    plugins = plugins_disco.PluginsRegistry.find_all()

    # note: arg parser internally handles --help (and exits afterwards)
    args = cli.prepare_and_parse_args(plugins, cli_args)
    config = configuration.NamespaceConfig(args)
    zope.component.provideUtility(config)

    make_or_verify_core_dir(config.config_dir, constants.CONFIG_DIRS_MODE,
                            os.geteuid(), config.strict_permissions)
    make_or_verify_core_dir(config.work_dir, constants.CONFIG_DIRS_MODE,
                            os.geteuid(), config.strict_permissions)
    # TODO: logs might contain sensitive data such as contents of the
    # private key! #525
    make_or_verify_core_dir(config.logs_dir, 0o700,
                            os.geteuid(), config.strict_permissions)
    # Setup logging ASAP, otherwise "No handlers could be found for
    # logger ..." TODO: this should be done before plugins discovery
    setup_logging(config)
    cli.possible_deprecation_warning(config)

    logger.debug("certbot version: %s", certbot.__version__)
    # do not log `config`, as it contains sensitive data (e.g. revoke --key)!
    logger.debug("Arguments: %r", cli_args)
    logger.debug("Discovered plugins: %r", plugins)

    sys.excepthook = functools.partial(_handle_exception, config=config)

    # Displayer
    if config.quiet:
        config.noninteractive_mode = True
        displayer = display_util.NoninteractiveDisplay(open(os.devnull, "w"))
    elif config.noninteractive_mode:
        displayer = display_util.NoninteractiveDisplay(sys.stdout)
    elif config.text_mode:
        displayer = display_util.FileDisplay(sys.stdout)
    else:
        displayer = display_util.NcursesDisplay()
    zope.component.provideUtility(displayer)

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
