"""Let's Encrypt CLI."""
# TODO: Sanity check all input.  Be sure to avoid shell code etc...
import argparse
import collections
import logging
import pkg_resources
import sys

import configargparse
import zope.component
import zope.interface.exceptions
import zope.interface.verify

import letsencrypt

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


def _common_run(args, config, authenticator, installer):
    if args.domains is None:
        doms = display_ops.choose_names(installer)
    else:
        doms = args.domains

    if not doms:
        return

    # Prepare for init of Client
    if args.authkey is None:
        authkey = client.init_key(config.rsa_key_size, config.key_dir)
    else:
        authkey = le_util.Key(args.authkey[0], args.authkey[1])

    acme = client.Client(config, authkey, authenticator, installer)

    # Validate the key and csr
    client.validate_key_csr(authkey)

    return acme, doms, authkey


def run(args, config):
    """Obtain a certificate and install."""
    if not args.eula:
        display_eula()

    if args.configurator is not None and (args.installer is not None or
                                          args.authenticator is not None):
        return ("Either --configurator or --authenticator/--installer"
                "pair, but not both, is allowed")

    if args.authenticator is not None or args.installer is not None:
        installer = plugins_disco.pick_installer(
            config, args.installer)
        authenticator = plugins_disco.pick_authenticator(
            config, args.authenticator)
    else:
        authenticator = installer = plugins_disco.pick_configurator(
            config, args.configurator)

    if installer is None or authenticator is None:
        return "Configurator could not be determined"

    acme, auth, installer, doms, auth_key = _common_run(args, config)
    cert_file, chain_file = acme.obtain_certificate(doms)
    acme.deploy_certificate(doms, authkey, cert_file, chain_file)
    acme.enhance_config(doms, args.redirect)


def auth(args, config):
    """Obtain a certificate (no install)."""
    authenticator = plugins_disco.pick_authenticator(config, args.authenticator)
    if authenticator is None:
        return "Authenticator could not be determined"

    if args.installer is not None:
        installer = plugins_disco.pick_installer(config, args.installer)
    else:
        installer = None

    if args.domains is None:
        if args.installer is not None:
            return ("--domains not set and provided --installer does not "
                    "help in autodiscovery")
        else:
           return ("Please specify --domains, or --installer that will "
                   "help in domain names autodiscovery")

    acme, doms, _ = _common_run(
        args, config, authenticator=authenticator, installer=None)
    acme.obtain_certificate(doms)


def install(args, config):
    """Install (no auth)."""
    installer = plugins_disco.pick_installer(config, args.installer)
    if installer is None:
        return "Installer could not be determined"
    acme, doms, authkey = _common_run(
        args, config, authenticator=None, installer=installer)
    assert args.cert_file is not None and args.chain_file is not None
    acme.deploy_certificate(doms, authkey, args.cert_file, args.chain_file)
    acme.enhance_config(doms, args.redirect)


def revoke(args, config):
    """Revoke."""
    if args.rev_cert is None and args.rev_key is None:
        return "At least one of --certificate or --key is required"
    client.revoke(config, args.no_confirm, args.rev_cert, args.rev_key)


def rollback(args, config):
    """Rollback."""
    client.rollback(args.checkpoints, config)


def config_changes(args, config):
    """View config changes.

    View checkpoints and associated configuration changes.

    """
    print args, config
    client.config_changes(config)


def _print_plugins(filtered, plugins, names):
    if not filtered:
        print "No plugins found"

    for plugin_cls, content in filtered.iteritems():
        print "* {0}".format(names[plugin_cls])
        print "Description: {0}".format(plugin_cls.description)
        print "Interfaces: {0}".format(", ".join(
            iface.__name__ for iface in zope.interface.implementedBy(
                plugin_cls)))
        print "Entry points:"
        for entry_point in plugins[plugin_cls]:
            print "- {0.dist}: {0}".format(entry_point)

        # if filtered == prepared:
        if isinstance(content, tuple) and content[1] is not None:
            print content[1]  # error
        print


def plugins(args, config):
    """List plugins."""
    plugins = plugins_disco.find_plugins()
    logging.debug("Discovered plugins: %s", plugins)

    names = plugins_disco.name_plugins(plugins)

    ifaces = [] if args.ifaces is None else args.ifaces
    filtered = plugins_disco.filter_plugins(
        plugins, *((iface,) for iface in ifaces))
    logging.debug("Filtered plugins: %s", filtered)

    if not args.init and not args.prepare:
        return _print_plugins(filtered, plugins, names)

    initialized = dict((plugin_cls, plugin_cls(config))
                       for plugin_cls in filtered)
    verified = plugins_disco.verify_plugins(initialized, ifaces)
    logging.debug("Verified plugins: %s", initialized)

    if not args.prepare:
        return _print_plugins(initialized, plugins, names)

    prepared = plugins_disco.prepare_plugins(initialized)
    logging.debug("Prepared plugins: %s", plugins)

    _print_plugins(prepared, plugins, names)
    plugins_disco


def display_eula():
    """Displays the end user agreement."""
    eula = pkg_resources.resource_string("letsencrypt", "EULA")
    if not zope.component.getUtility(interfaces.IDisplay).yesno(
            eula, "Agree", "Cancel"):
        sys.exit(0)


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


def create_parser():
    """Create parser."""
    parser = configargparse.ArgParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        args_for_setting_config_path=["-c", "--config"],
        default_config_files=constants.DEFAULT_CONFIG_FILES)

    # --help is automatically provided by argparse
    parser.add_argument(
        "--version", action="version", version="%(prog)s {0}".format(
            letsencrypt.__version__))
    parser.add_argument(
        "-v", "--verbose", dest="verbose_count", action="count",
        default=constants.DEFAULT_VERBOSE_COUNT)

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

    parser_plugins = add_subparser("plugins", plugins)
    parser_plugins.add_argument("--init", action="store_true")
    parser_plugins.add_argument("--prepare", action="store_true")
    parser_plugins.add_argument(
        "--authenticators", action="append_const", dest="ifaces",
        const=interfaces.IAuthenticator)
    parser_plugins.add_argument(
        "--installers", action="append_const", dest="ifaces",
        const=interfaces.IInstaller)

    add = parser.add_argument
    config_help = lambda name: interfaces.IConfig[name].__doc__

    parser_run.add_argument("--configurator")
    for subparser in parser_run, parser_auth:
        subparser.add_argument("-a", "--authenticator")
    for subparser in parser_run, parser_auth, parser_install:
        # parser_auth uses --installer for domains autodiscovery
        subparser.add_argument("-i", "--installer")
    # positional arg shadows --domains, instead of appending, and
    # --domains is useful, because it can be stored in config
    #for subparser in parser_run, parser_auth, parser_install:
    #    subparser.add_argument("domains", nargs="*", metavar="domain")

    add("-d", "--domains", metavar="DOMAIN", action="append")
    add("-s", "--server", default=constants.DEFAULT_SERVER,
        help=config_help("server"))

    add("-k", "--authkey", type=read_file,
        help="Path to the authorized key file")
    add("-B", "--rsa-key-size", type=int, metavar="N",
        default=constants.DEFAULT_RSA_KEY_SIZE,
        help=config_help("rsa_key_size"))

    parser_revoke.add_argument(
        "--certificate", dest="rev_cert", type=read_file, metavar="CERT_PATH",
        help="Revoke a specific certificate.")
    parser_revoke.add_argument(
        "--key", dest="rev_key", type=read_file, metavar="KEY_PATH",
        help="Revoke all certs generated by the provided authorized key.")

    parser_rollback.add_argument(
        "--checkpoints", type=int, metavar="N",
        default=constants.DEFAULT_ROLLBACK_CHECKPOINTS,
        help="Revert configuration N number of checkpoints.")

    # TODO: resolve - assumes binary logic while client.py assumes ternary.
    add("-r", "--redirect", action="store_true",
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.")

    add("--no-confirm", dest="no_confirm", action="store_true",
        help="Turn off confirmation screens, currently used for --revoke")

    add("-e", "--agree-tos", dest="eula", action="store_true",
        help="Skip the end user license agreement screen.")
    add("-t", "--text", dest="use_curses", action="store_false",
        help="Use the text output instead of the curses UI.")

    add("--config-dir", default=constants.DEFAULT_CONFIG_DIR,
        help=config_help("config_dir"))
    add("--work-dir", default=constants.DEFAULT_WORK_DIR,
        help=config_help("work_dir"))
    add("--backup-dir", default=constants.DEFAULT_BACKUP_DIR,
        help=config_help("backup_dir"))
    add("--key-dir", default=constants.DEFAULT_KEY_DIR,
        help=config_help("key_dir"))
    add("--cert-dir", default=constants.DEFAULT_CERTS_DIR,
        help=config_help("cert_dir"))

    add("--le-vhost-ext", default="-le-ssl.conf",
        help=config_help("le_vhost_ext"))
    add("--cert-path", default=constants.DEFAULT_CERT_PATH,
        help=config_help("cert_path"))
    add("--chain-path", default=constants.DEFAULT_CHAIN_PATH,
        help=config_help("chain_path"))

    add("--apache-server-root", default=constants.DEFAULT_APACHE_SERVER_ROOT,
        help=config_help("apache_server_root"))
    add("--apache-mod-ssl-conf", default=constants.DEFAULT_APACHE_MOD_SSL_CONF,
        help=config_help("apache_mod_ssl_conf"))
    add("--apache-ctl", default=constants.DEFAULT_APACHE_CTL,
        help=config_help("apache_ctl"))
    add("--apache-enmod", default=constants.DEFAULT_APACHE_ENMOD,
        help=config_help("apache_enmod"))
    add("--apache-init-script", default=constants.DEFAULT_APACHE_INIT_SCRIPT,
        help=config_help("apache_init_script"))

    return parser


def main():  # pylint: disable=too-many-branches, too-many-statements
    """Command line argument parsing and main script execution."""
    # note: arg parser internally handles --help (and exits afterwards)
    args = create_parser().parse_args()
    config = configuration.NamespaceConfig(args)

    # note: check is done after arg parsing as --help should work w/o root also.
    #if not os.geteuid() == 0:
    #    return (
    #        "{0}Root is required to run letsencrypt.  Please use sudo.{0}"
    #        .format(os.linesep))

    # Set up logging
    level = -args.verbose_count * 10
    logger = logging.getLogger()
    logger.setLevel(level)
    logging.debug("Logging level set at %d", level)
    # displayer
    if args.use_curses:
        logger.addHandler(log.DialogHandler())
        displayer = display_util.NcursesDisplay()
    else:
        displayer = display_util.FileDisplay(sys.stdout)
    zope.component.provideUtility(displayer)

    return args.func(args, config)


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
