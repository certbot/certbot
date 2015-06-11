"""Let's Encrypt CLI."""
# TODO: Sanity check all input.  Be sure to avoid shell code etc...
import argparse
import atexit
import logging
import os
import sys

import configargparse
import zope.component
import zope.interface.exceptions
import zope.interface.verify

import letsencrypt

from letsencrypt import account
from letsencrypt import configuration
from letsencrypt import constants
from letsencrypt import client
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import le_util
from letsencrypt import log
from letsencrypt import reporter

from letsencrypt.display import util as display_util
from letsencrypt.display import ops as display_ops

from letsencrypt.plugins import disco as plugins_disco


def _account_init(args, config):
    le_util.make_or_verify_dir(
        config.config_dir, constants.CONFIG_DIRS_MODE, os.geteuid())

    # Prepare for init of Client
    if args.email is None:
        return client.determine_account(config)
    else:
        try:
            # The way to get the default would be args.email = ""
            # First try existing account
            return account.Account.from_existing_account(config, args.email)
        except errors.LetsEncryptClientError:
            try:
                # Try to make an account based on the email address
                return account.Account.from_email(config, args.email)
            except errors.LetsEncryptClientError:
                return None


def _common_run(args, config, acc, authenticator, installer):
    if args.domains is None:
        doms = display_ops.choose_names(installer)
    else:
        doms = args.domains

    if not doms:
        sys.exit("Please specify --domains, or --installer that will "
                 "help in domain names autodiscovery")

    acme = client.Client(config, acc, authenticator, installer)

    # Validate the key and csr
    client.validate_key_csr(acc.key)

    if authenticator is not None:
        if acc.regr is None:
            try:
                acme.register()
            except errors.LetsEncryptClientError:
                sys.exit("Unable to register an account with ACME server")

    return acme, doms


def run(args, config, plugins):
    """Obtain a certificate and install."""
    acc = _account_init(args, config)
    if acc is None:
        return None

    if args.configurator is not None and (args.installer is not None or
                                          args.authenticator is not None):
        return ("Either --configurator or --authenticator/--installer"
                "pair, but not both, is allowed")

    if args.authenticator is not None or args.installer is not None:
        installer = display_ops.pick_installer(
            config, args.installer, plugins)
        authenticator = display_ops.pick_authenticator(
            config, args.authenticator, plugins)
    else:
        # TODO: this assume that user doesn't want to pick authenticator
        #       and installer separately...
        authenticator = installer = display_ops.pick_configurator(
            config, args.configurator, plugins)

    if installer is None or authenticator is None:
        return "Configurator could not be determined"

    acme, doms = _common_run(args, config, acc, authenticator, installer)
    # TODO: Handle errors from _common_run?
    lineage = acme.obtain_and_enroll_certificate(doms, authenticator,
                                                 installer, plugins)
    if not lineage:
        return "Certificate could not be obtained"
    acme.deploy_certificate(doms, lineage.privkey, lineage.cert, lineage.chain)
    acme.enhance_config(doms, args.redirect)


def auth(args, config, plugins):
    """Obtain a certificate (no install)."""
    # XXX: Update for renewer / RenewableCert
    acc = _account_init(args, config)
    if acc is None:
        return None

    authenticator = display_ops.pick_authenticator(
        config, args.authenticator, plugins)
    if authenticator is None:
        return "Authenticator could not be determined"

    if args.installer is not None:
        installer = display_ops.pick_installer(config, args.installer, plugins)
    else:
        installer = None

    # TODO: Handle errors from _common_run?
    acme, doms = _common_run(
        args, config, acc, authenticator=authenticator, installer=installer)
    if not acme.obtain_and_enroll_certificate(doms, authenticator, installer,
                                              plugins):
        return "Certificate could not be obtained"


def install(args, config, plugins):
    """Install (no auth)."""
    # XXX: Update for renewer/RenewableCert
    acc = _account_init(args, config)
    if acc is None:
        return None

    installer = display_ops.pick_installer(config, args.installer, plugins)
    if installer is None:
        return "Installer could not be determined"
    acme, doms = _common_run(
        args, config, acc, authenticator=None, installer=installer)
    assert args.cert_path is not None
    acme.deploy_certificate(doms, acc.key.file, args.cert_path, args.chain_path)
    acme.enhance_config(doms, args.redirect)


def revoke(args, unused_config, unused_plugins):
    """Revoke."""
    if args.rev_cert is None and args.rev_key is None:
        return "At least one of --certificate or --key is required"

    # This depends on the renewal config and cannot be completed yet.
    zope.component.getUtility(interfaces.IDisplay).notification(
        "Revocation is not available with the new Boulder server yet.")
    #client.revoke(args.installer, config, plugins, args.no_confirm,
    #              args.rev_cert, args.rev_key)


def rollback(args, config, plugins):
    """Rollback."""
    client.rollback(args.installer, args.checkpoints, config, plugins)


def config_changes(unused_args, config, unused_plugins):
    """View config changes.

    View checkpoints and associated configuration changes.

    """
    client.view_config_changes(config)


def plugins_cmd(args, config, plugins):  # TODO: Use IDiplay rathern than print
    """List plugins."""
    logging.debug("Expected interfaces: %s", args.ifaces)

    ifaces = [] if args.ifaces is None else args.ifaces
    filtered = plugins.ifaces(ifaces)
    logging.debug("Filtered plugins: %r", filtered)

    if not args.init and not args.prepare:
        print str(filtered)
        return

    filtered.init(config)
    verified = filtered.verify(ifaces)
    logging.debug("Verified plugins: %r", verified)

    if not args.prepare:
        print str(verified)
        return

    verified.prepare()
    available = verified.available()
    logging.debug("Prepared plugins: %s", available)
    print str(available)


def read_file(filename):
    """Returns the given file's contents with universal new line support.

    :param str filename: Filename

    :returns: A tuple of filename and its contents
    :rtype: tuple

    :raises argparse.ArgumentTypeError: File does not exist or is not readable.

    """
    try:
        return filename, open(filename, "rU").read()
    except IOError as exc:
        raise argparse.ArgumentTypeError(exc.strerror)


def flag_default(name):
    """Default value for CLI flag."""
    return constants.CLI_DEFAULTS[name]

def config_help(name):
    """Help message for `.IConfig` attribute."""
    return interfaces.IConfig[name].__doc__


def create_parser(plugins):
    """Create parser."""
    parser = configargparse.ArgParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        args_for_setting_config_path=["-c", "--config"],
        default_config_files=flag_default("config_files"))
    add = parser.add_argument

    # --help is automatically provided by argparse
    add("--version", action="version", version="%(prog)s {0}".format(
        letsencrypt.__version__))
    add("-v", "--verbose", dest="verbose_count", action="count",
        default=flag_default("verbose_count"), help="This flag can be used "
        "multiple times to incrementally increase the verbosity of output, "
        "e.g. -vvv.")
    add("--no-confirm", dest="no_confirm", action="store_true",
        help="Turn off confirmation screens, currently used for --revoke")
    add("-e", "--agree-tos", dest="tos", action="store_true",
        help="Skip the end user license agreement screen.")
    add("-t", "--text", dest="text_mode", action="store_true",
        help="Use the text output instead of the curses UI.")

    testing_group = parser.add_argument_group(
        "testing", description="The following flags are meant for "
        "testing purposes only! Do NOT change them, unless you "
        "really know what you're doing!")
    testing_group.add_argument(
        "--no-verify-ssl", action="store_true",
        help=config_help("no_verify_ssl"),
        default=flag_default("no_verify_ssl"))
    # TODO: apache and nginx plugins do NOT respect it
    testing_group.add_argument(
        "--dvsni-port", type=int, help=config_help("dvsni_port"),
        default=flag_default("dvsni_port"))

    subparsers = parser.add_subparsers(metavar="SUBCOMMAND")
    def add_subparser(name, func):  # pylint: disable=missing-docstring
        subparser = subparsers.add_parser(
            name, help=func.__doc__.splitlines()[0], description=func.__doc__)
        subparser.set_defaults(func=func)
        return subparser

    add_subparser("run", run)
    add_subparser("auth", auth)
    add_subparser("install", install)
    parser_revoke = add_subparser("revoke", revoke)
    parser_rollback = add_subparser("rollback", rollback)
    add_subparser("config_changes", config_changes)

    parser_plugins = add_subparser("plugins", plugins_cmd)
    parser_plugins.add_argument("--init", action="store_true")
    parser_plugins.add_argument("--prepare", action="store_true")
    parser_plugins.add_argument(
        "--authenticators", action="append_const", dest="ifaces",
        const=interfaces.IAuthenticator)
    parser_plugins.add_argument(
        "--installers", action="append_const", dest="ifaces",
        const=interfaces.IInstaller)

    parser.add_argument("--configurator")
    parser.add_argument("-a", "--authenticator")
    parser.add_argument("-i", "--installer")

    # positional arg shadows --domains, instead of appending, and
    # --domains is useful, because it can be stored in config
    #for subparser in parser_run, parser_auth, parser_install:
    #    subparser.add_argument("domains", nargs="*", metavar="domain")

    add("-d", "--domains", metavar="DOMAIN", action="append")
    add("-s", "--server", default=flag_default("server"),
        help=config_help("server"))
    add("-k", "--authkey", type=read_file,
        help="Path to the authorized key file")
    add("-m", "--email", help=config_help("email"))
    add("-B", "--rsa-key-size", type=int, metavar="N",
        default=flag_default("rsa_key_size"), help=config_help("rsa_key_size"))
    # TODO: resolve - assumes binary logic while client.py assumes ternary.
    add("-r", "--redirect", action="store_true",
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.")

    parser_revoke.add_argument(
        "--certificate", dest="rev_cert", type=read_file, metavar="CERT_PATH",
        help="Revoke a specific certificate.")
    parser_revoke.add_argument(
        "--key", dest="rev_key", type=read_file, metavar="KEY_PATH",
        help="Revoke all certs generated by the provided authorized key.")

    parser_rollback.add_argument(
        "--checkpoints", type=int, metavar="N",
        default=flag_default("rollback_checkpoints"),
        help="Revert configuration N number of checkpoints.")

    _paths_parser(parser.add_argument_group("paths"))

    # TODO: plugin_parser should be called for every detected plugin
    for name, plugin_ep in plugins.iteritems():
        plugin_ep.plugin_cls.inject_parser_options(
            parser.add_argument_group(
                name, description=plugin_ep.description), name)

    return parser


def _paths_parser(parser):
    add = parser.add_argument
    add("--config-dir", default=flag_default("config_dir"),
        help=config_help("config_dir"))
    add("--work-dir", default=flag_default("work_dir"),
        help=config_help("work_dir"))
    add("--backup-dir", default=flag_default("backup_dir"),
        help=config_help("backup_dir"))
    add("--key-dir", default=flag_default("key_dir"),
        help=config_help("key_dir"))
    add("--cert-dir", default=flag_default("certs_dir"),
        help=config_help("cert_dir"))

    add("--le-vhost-ext", default="-le-ssl.conf",
        help=config_help("le_vhost_ext"))
    add("--cert-path", default=flag_default("cert_path"),
        help=config_help("cert_path"))
    add("--chain-path", default=flag_default("chain_path"),
        help=config_help("chain_path"))

    add("--renewer-config-file", default=flag_default("renewer_config_file"),
        help=config_help("renewer_config_file"))

    return parser


def main(args=sys.argv[1:]):
    """Command line argument parsing and main script execution."""
    # note: arg parser internally handles --help (and exits afterwards)
    plugins = plugins_disco.PluginsRegistry.find_all()
    args = create_parser(plugins).parse_args(args)
    config = configuration.NamespaceConfig(args)

    # Displayer
    if args.text_mode:
        displayer = display_util.FileDisplay(sys.stdout)
    else:
        displayer = display_util.NcursesDisplay()
    zope.component.provideUtility(displayer)

    # Reporter
    report = reporter.Reporter()
    zope.component.provideUtility(report)
    atexit.register(report.atexit_print_messages)

    # Logging
    level = -args.verbose_count * 10
    logger = logging.getLogger()
    logger.setLevel(level)
    logging.debug("Logging level set at %d", level)
    if not args.text_mode:
        logger.addHandler(log.DialogHandler())

    logging.debug("Discovered plugins: %r", plugins)

    if not os.geteuid() == 0:
        logging.warning(
            "Root (sudo) is required to run most of letsencrypt functionality.")
        # check must be done after arg parsing as --help should work
        # w/o root; on the other hand, e.g. "letsencrypt run
        # --authenticator dns" or "letsencrypt plugins" does not
        # require root as well
        #return (
        #    "{0}Root is required to run letsencrypt.  Please use sudo.{0}"
        #    .format(os.linesep))

    return args.func(args, config, plugins)


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
