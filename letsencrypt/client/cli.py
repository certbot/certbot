"""Let's Encrypt CLI."""
# TODO: Sanity check all input.  Be sure to avoid shell code etc...
import argparse
import collections
import logging
import os
import pkg_resources
import sys

import configargparse
import zope.component
import zope.interface.exceptions
import zope.interface.verify

import letsencrypt

from letsencrypt.client import account
from letsencrypt.client import configuration
from letsencrypt.client import constants
from letsencrypt.client import client
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util
from letsencrypt.client import log

from letsencrypt.client.display import util as display_util
from letsencrypt.client.display import ops as display_ops

from letsencrypt.client.plugins import disco as plugins_disco

from letsencrypt.client.plugins.apache import configurator as apache_configurator
from letsencrypt.client.plugins.nginx import configurator as nginx_configurator


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
                return None

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
        installer = plugins_disco.pick_installer(
            config, args.installer, plugins)
        authenticator = plugins_disco.pick_authenticator(
            config, args.authenticator, plugins)
    else:
        # TODO: this assume that user doesn't want to pick authenticator
        #       and installer separately...
        authenticator = installer = plugins_disco.pick_configurator(
            config, args.configurator, plugins)

    if installer is None or authenticator is None:
        return "Configurator could not be determined"

    acme, doms = _common_run(args, config, acc, authenticator, installer)
    cert_path, chain_path = acme.obtain_certificate(doms)
    acme.deploy_certificate(doms, acc.key, cert_path, chain_path)
    acme.enhance_config(doms, args.redirect)


def auth(args, config, plugins):
    """Obtain a certificate (no install)."""
    acc = _account_init(args, config)
    if acc is None:
        return None

    authenticator = plugins_disco.pick_authenticator(
        config, args.authenticator, plugins)
    if authenticator is None:
        return "Authenticator could not be determined"

    if args.installer is not None:
        installer = plugins_disco.pick_installer(config, args.installer, plugins)
    else:
        installer = None

    acme, doms = _common_run(
        args, config, acc, authenticator=authenticator, installer=None)
    acme.obtain_certificate(doms)


def install(args, config, plugins):
    """Install (no auth)."""
    acc = _account_init(args, config)
    if acc is None:
        return None

    installer = plugins_disco.pick_installer(config, args.installer, plugins)
    if installer is None:
        return "Installer could not be determined"
    acme, doms = _common_run(
        args, config, acc, authenticator=None, installer=installer)
    assert args.cert_path is not None and args.chain_path is not None
    acme.deploy_certificate(doms, acc.key, args.cert_path, args.chain_path)
    acme.enhance_config(doms, args.redirect)


def revoke(args, config, plugins):
    """Revoke."""
    if args.rev_cert is None and args.rev_key is None:
        return "At least one of --certificate or --key is required"

    # This depends on the renewal config and cannot be completed yet.
    zope.component.getUtility(interfaces.IDisplay).notification(
        "Revocation is not available with the new Boulder server yet.")
    #client.revoke(config, args.no_confirm, args.rev_cert, args.rev_key)


def rollback(args, config, plugins):
    """Rollback."""
    client.rollback(args.checkpoints, config)


def config_changes(args, config, plugins):
    """View config changes.

    View checkpoints and associated configuration changes.

    """
    client.config_changes(config)


def _print_plugins(plugins):
    # TODO: this functions should use IDisplay rather than printing

    if not plugins:
        print "No plugins found"

    for plugin_ep in plugins.itervalues():
        print "* {0}".format(plugin_ep.name)
        print "Description: {0}".format(plugin_ep.plugin_cls.description)
        print "Interfaces: {0}".format(", ".join(
            iface.__name__ for iface in zope.interface.implementedBy(
                plugin_ep.plugin_cls)))
        print "Entry point: {0}".format(plugin_ep.entry_point)

        if plugin_ep.initialized:
            print "Initialized: {0}".format(plugin_ep.init())

        # if filtered == prepared:
        #if isinstance(content, tuple) and content[1] is not None:
        #    print content[1]  # error

        print  # whitespace between plugins


def plugins_cmd(args, config, plugins):
    """List plugins."""
    logging.debug("Discovered plugins: %s", plugins)

    ifaces = [] if args.ifaces is None else args.ifaces
    filtered = plugins.filter(*((iface,) for iface in ifaces))
    logging.debug("Filtered plugins: %s", filtered)

    if not args.init and not args.prepare:
        return _print_plugins(filtered)

    for plugin_ep in filtered.itervalues():
        plugin_ep.init(config)
    #verified = plugins_disco.verify_plugins(initialized, ifaces)
    #logging.debug("Verified plugins: %s", initialized)

    if not args.prepare:
        return _print_plugins(filtered)

    prepared = plugins_disco.prepare_plugins(initialized)
    logging.debug("Prepared plugins: %s", plugins)

    _print_plugins(prepared, plugins, names)
    plugins_disco


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
        default=flag_default("verbose_count"))
    add("--no-confirm", dest="no_confirm", action="store_true",
        help="Turn off confirmation screens, currently used for --revoke")
    add("-e", "--agree-tos", dest="tos", action="store_true",
        help="Skip the end user license agreement screen.")
    add("-t", "--text", dest="use_curses", action="store_false",
        help="Use the text output instead of the curses UI.")

    subparsers = parser.add_subparsers(metavar="SUBCOMMAND")
    def add_subparser(name, func):
        subparser = subparsers.add_parser(
            name, help=func.__doc__.splitlines()[0], description=func.__doc__)
        subparser.set_defaults(func=func)
        return subparser

    parser_run = add_subparser("run", run)
    parser_auth = add_subparser("auth", auth)
    parser_install = add_subparser("install", install)
    parser_revoke = add_subparser("revoke", revoke)
    parser_rollback = add_subparser("rollback", rollback)
    parrser_config_changes = add_subparser("config_changes", config_changes)

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

    paths_parser(parser.add_argument_group("paths"))

    # TODO: plugin_parser should be called for every detected plugin
    for name, plugin_ep in plugins.iteritems():
        plugin_ep.plugin_cls.inject_parser_options(
            parser.add_argument_group(name), name)

    return parser


def paths_parser(parser):
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

    return parser


def main(args=sys.argv[1:]):
    """Command line argument parsing and main script execution."""
    # note: arg parser internally handles --help (and exits afterwards)
    plugins = plugins_disco.PluginsRegistry.find_all()
    args = create_parser(plugins).parse_args(args)
    config = configuration.NamespaceConfig(args)

    # Displayer
    if args.use_curses:
        displayer = display_util.NcursesDisplay()
    else:
        displayer = display_util.FileDisplay(sys.stdout)
    zope.component.provideUtility(displayer)

    # Logging
    level = -args.verbose_count * 10
    logger = logging.getLogger()
    logger.setLevel(level)
    logging.debug("Logging level set at %d", level)
    if args.use_curses:
        logger.addHandler(log.DialogHandler())

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
