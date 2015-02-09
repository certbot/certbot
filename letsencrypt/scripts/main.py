#!/usr/bin/env python
"""Parse command line and call the appropriate functions.

..todo:: Sanity check all input.  Be sure to avoid shell code etc...

"""
import argparse
import logging
import os
import sys

import confargparse
import zope.component

import letsencrypt

from letsencrypt.client import configuration
from letsencrypt.client import client
from letsencrypt.client import display
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import log

def create_parser():
    """Create parser."""
    parser = confargparse.ConfArgParser(
        description="letsencrypt client %s" % letsencrypt.__version__)

    add = parser.add_argument
    config_help = lambda name: interfaces.IConfig[name].__doc__

    add("-d", "--domains", metavar="DOMAIN", nargs="+")
    add("-s", "--server", default="letsencrypt-demo.org:443",
        help=config_help("server"))

    add("-p", "--privkey", type=read_file,
        help="Path to the private key file for certificate generation.")
    add("-B", "--rsa-key-size", type=int, default=2048, metavar="N",
        help=config_help("rsa_key_size"))

    add("-k", "--revoke", action="store_true", help="Revoke a certificate.")
    add("-b", "--rollback", type=int, default=0, metavar="N",
        help="Revert configuration N number of checkpoints.")
    add("-v", "--view-config-changes", action="store_true",
        help="View checkpoints and associated configuration changes.")
    add("-r", "--redirect", type=bool, default=None,
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.")

    add("-e", "--agree-tos", dest="eula", action="store_true",
        help="Skip the end user license agreement screen.")
    add("-t", "--text", dest="use_curses", action="store_false",
        help="Use the text output instead of the curses UI.")

    add("--config-dir", default="/etc/letsencrypt",
        help=config_help("config_dir"))
    add("--work-dir", default="/var/lib/letsencrypt",
        help=config_help("work_dir"))
    add("--backup-dir", default="/var/lib/letsencrypt/backups",
        help=config_help("backup_dir"))
    add("--key-dir", default="/etc/letsencrypt/keys",
        help=config_help("key_dir"))
    add("--cert-dir", default="/etc/letsencrypt/certs",
        help=config_help("cert_dir"))

    add("--le-vhost-ext", default="-le-ssl.conf",
        help=config_help("le_vhost_ext"))
    add("--cert-path", default="/etc/letsencrypt/certs/cert-letsencrypt.pem",
        help=config_help("cert_path"))
    add("--chain-path", default="/etc/letsencrypt/certs/chain-letsencrypt.pem",
        help=config_help("chain_path"))

    add("--apache-server-root", default="/etc/apache2",
        help=config_help("apache_server_root"))
    add("--apache-mod-ssl-conf", default="/etc/letsencrypt/options-ssl.conf",
        help=config_help("apache_mod_ssl_conf"))
    add("--apache-ctl", default="apache2ctl", help=config_help("apache_ctl"))
    add("--apache-enmod", default="a2enmod", help=config_help("apache_enmod"))
    add("--apache-init-script", default="/etc/init.d/apache2",
        help=config_help("apache_init_script"))

    return parser


def main():  # pylint: disable=too-many-branches
    """Command line argument parsing and main script execution."""
    # note: arg parser internally handles --help (and exits afterwards)
    args = create_parser().parse_args()
    config = configuration.NamespaceConfig(args)

    # note: check is done after arg parsing as --help should work w/o root also.
    if not os.geteuid() == 0:
        sys.exit(
            "{0}Root is required to run letsencrypt.  Please use sudo.{0}"
            .format(os.linesep))

    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if args.use_curses:
        logger.addHandler(log.DialogHandler())
        displayer = display.NcursesDisplay()
    else:
        displayer = display.FileDisplay(sys.stdout)
    zope.component.provideUtility(displayer)

    if args.view_config_changes:
        client.view_config_changes(config)
        sys.exit()

    if args.revoke:
        client.revoke(config)
        sys.exit()

    if args.rollback > 0:
        client.rollback(args.rollback, config)
        sys.exit()

    if not args.eula:
        display_eula()

    # Make sure we actually get an installer that is functioning properly
    # before we begin to try to use it.
    try:
        installer = client.determine_installer(config)
    except errors.LetsEncryptMisconfigurationError as err:
        logging.fatal("Please fix your configuration before proceeding.  "
                      "The Installer exited with the following message: "
                      "%s", err)
        sys.exit(1)

    # Use the same object if possible
    if interfaces.IAuthenticator.providedBy(installer):  # pylint: disable=no-member
        auth = installer
    else:
        auth = client.determine_authenticator(config)

    if args.domains is None:
        domains = choose_names(installer)

    # Prepare for init of Client
    if args.privkey is None:
        privkey = client.init_key(args.rsa_key_size, config.key_dir)
    else:
        privkey = client.Client.Key(args.privkey[0], args.privkey[1])

    acme = client.Client(config, privkey, auth, installer)

    # Validate the key and csr
    client.validate_key_csr(privkey)

    # This more closely mimics the capabilities of the CLI
    # It should be possible for reconfig only, install-only, no-install
    # I am not sure the best way to handle all of the unimplemented abilities,
    # but this code should be safe on all environments.
    if auth is not None:
        cert_file, chain_file = acme.obtain_certificate(domains)
    if installer is not None and cert_file is not None:
        acme.deploy_certificate(domains, privkey, cert_file, chain_file)
    if installer is not None:
        acme.enhance_config(domains, args.redirect)


def display_eula():
    """Displays the end user agreement."""
    with open('EULA') as eula_file:
        if not zope.component.getUtility(interfaces.IDisplay).generic_yesno(
                eula_file.read(), "Agree", "Cancel"):
            sys.exit(0)


def choose_names(installer):
    """Display screen to select domains to validate.

    :param installer: An installer object
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    """
    # This function adds all names found in the installer configuration
    # Then filters them based on user selection
    code, names = zope.component.getUtility(
        interfaces.IDisplay).filter_names(get_all_names(installer))
    if code == display.OK and names:
        return names
    else:
        sys.exit(0)


def get_all_names(installer):
    """Return all valid names in the configuration.

    :param installer: An installer object
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    """
    names = list(installer.get_all_names())

    if not names:
        logging.fatal("No domain names were found in your installation")
        logging.fatal("Either specify which names you would like "
                      "letsencrypt to validate or add server names "
                      "to your virtual hosts")
        sys.exit(1)

    return names


def read_file(filename):
    """Returns the given file's contents with universal new line support.

    :param str filename: Filename

    :returns: A tuple of filename and its contents
    :rtype: tuple

    :raises argparse.ArgumentTypeError: File does not exist or is not readable.

    """
    try:
        return filename, open(filename, 'rU').read()
    except IOError as exc:
        raise argparse.ArgumentTypeError(exc.strerror)


if __name__ == "__main__":
    main()
