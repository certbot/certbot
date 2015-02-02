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
import zope.interface

import letsencrypt

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

    add("-d", "--domains", metavar="DOMAIN", nargs="+")
    add("-s", "--acme-server", "--server", default="letsencrypt-demo.org:443",
        help="CA hostname (and optionally :port). The server certificate must "
             "be trusted in order to avoid further modifications to the "
             "client.")

    add("-p", "--privkey", type=read_file,
        help="Path to the private key file for certificate generation.")
    add("-B", "--rsa-key-size", type=int, default=2048,
        metavar="N", help="RSA key shall be sized N bits.")

    add("-k", "--revoke", action="store_true", help="Revoke a certificate.")
    add("-b", "--rollback", type=int, default=0, metavar="N",
        help="Revert configuration N number of checkpoints.")
    add("-v", "--view-config-changes", action="store_true",
        help="View checkpoints and associated configuration changes.")
    add("-r", "--redirect", action="store_true",
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost.")

    add("-e", "--agree-tos", dest="eula", action="store_true",
        help="Skip the end user license agreement screen.")
    add("-t", "--text", dest="use_curses", action="store_false",
        help="Use the text output instead of the curses UI.")
    add("--test", action="store_true", help="Run in test mode.")

    # TODO: trailing slashes might be important! check and remove
    add("--config-dir", default="/etc/letsencrypt/",
        help="Configuration directory.")
    add("--work-dir", default="/var/lib/letsencrypt/",
        help="Working directory.")
    add("--backup-dir", default="/var/lib/letsencrypt/backups/",
        help="Configuration backups directory.")
    add("--temp-checkpoint-dir",
        default="/var/lib/letsencrypt/temp_checkpoint/",
        help="Temporary checkpoint directory.")
    add("--in-progress-dir",
        default="/var/lib/letsencrypt/backups/IN_PROGRESS/",
        help="Directory used before a permanent checkpoint is finalized")
    add("--cert-key-backup", default="/var/lib/letsencrypt/keys-certs/",
        help="Directory where all certificates and keys are stored. "
             "Used for easy revocation.")
    add("--rev-tokens-dir", default="/var/lib/letsencrypt/revocation_tokens/",
        help="Directory where all revocation tokens are saved.")
    add("--key-dir", default="/etc/letsencrypt/keys/", help="Keys storage.")
    add("--cert-dir", default="/etc/letsencrypt/certs/",
        help="Certificates storage.")

    add("--le-vhost-ext", default="-le-ssl.conf",
        help="SSL vhost configuration extension.")
    add("--cert-path", default="/etc/letsencrypt/certs/cert-letsencrypt.pem",
        help="Let's Encrypt certificate file.")
    add("--chain-path", default="/etc/letsencrypt/certs/chain-letsencrypt.pem",
        help="Let's Encrypt chain file.")

    add("--apache-ctl", default="apache2ctl",
        help="Path to the 'apache2ctl' binary, used for 'configtest' and "
             "retrieving Apache2 version number.")
    add("--apache-enmod", default="a2enmod",
        help="Path to the Apache 'a2enmod' binary.")
    add("--apache-init-script", default="/etc/init.d/apache2",
        help="Path to the Apache init script (used for server reload/restart).")
    add("--apache-server-root", default="/etc/apache2",
        help="Apache server root directory.")
    add("--apache-mod-ssl-conf", default="/etc/letsencrypt/options-ssl.conf",
        help="Contains standard Apache SSL directives.")

    return parser

def main():  # pylint: disable=too-many-branches
    """Command line argument parsing and main script execution."""

    # note: arg parser internally handles --help (and exits afterwards)
    config = create_parser().parse_args()
    zope.interface.directlyProvides(config, interfaces.IConfig)

    # note: check is done after arg parsing as --help should work w/o root also.
    if not os.geteuid() == 0:
        sys.exit(
            "{0}Root is required to run letsencrypt.  Please use sudo.{0}"
            .format(os.linesep))

    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if config.use_curses:
        logger.addHandler(log.DialogHandler())
        displayer = display.NcursesDisplay()
    else:
        displayer = display.FileDisplay(sys.stdout)
    zope.component.provideUtility(displayer)

    if config.view_config_changes:
        client.view_config_changes(config)
        sys.exit()

    if config.revoke:
        client.revoke(config.acme_server, config)
        sys.exit()

    if config.rollback > 0:
        client.rollback(config.rollback, config)
        sys.exit()

    if not config.eula:
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

    if config.domains is None:
        domains = choose_names(installer)

    # Prepare for init of Client
    if config.privkey is None:
        privkey = client.init_key(config.rsa_key_size, config.key_dir)
    else:
        privkey = client.Client.Key(config.privkey[0], config.privkey[1])

    acme = client.Client(config.acme_server, privkey, auth, installer, config)

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
        acme.enhance_config(domains, config.redirect)


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
