#!/usr/bin/env python
"""Parse command line and call the appropriate functions."""
import argparse
import logging
import os
import sys

import zope.component

from letsencrypt.client import CONFIG
from letsencrypt.client import client
from letsencrypt.client import display
from letsencrypt.client import interfaces
from letsencrypt.client import errors
from letsencrypt.client import log
from letsencrypt.client import revoker
from letsencrypt.client.apache import configurator


def main():
    """Command line argument parsing and main script execution."""
    if not os.geteuid() == 0:
        sys.exit(
            "{0}Root is required to run letsencrypt.  Please use sudo.{0}"
            .format(os.linesep))

    parser = argparse.ArgumentParser(
        description="An ACME client that can update Apache configurations.")

    parser.add_argument("-d", "--domains", dest="domains", metavar="DOMAIN",
                        nargs="+")
    parser.add_argument("-s", "--server", dest="server",
                        default=CONFIG.ACME_SERVER,
                        help="The ACME CA server. [%(default)s]")
    parser.add_argument("-p", "--privkey", dest="privkey", type=read_file,
                        help="Path to the private key file for certificate "
                             "generation.")
    parser.add_argument("-b", "--rollback", dest="rollback", type=int,
                        default=0, metavar="N",
                        help="Revert configuration N number of checkpoints.")
    parser.add_argument("-k", "--revoke", dest="revoke", action="store_true",
                        help="Revoke a certificate.")
    parser.add_argument("-v", "--view-config-changes",
                        dest="view_config_changes",
                        action="store_true",
                        help="View checkpoints and associated configuration "
                             "changes.")
    parser.add_argument("-r", "--redirect", dest="redirect",
                        action="store_const", const=True,
                        help="Automatically redirect all HTTP traffic to HTTPS "
                             "for the newly authenticated vhost.")
    parser.add_argument("-n", "--no-redirect", dest="redirect",
                        action="store_const", const=False,
                        help="Skip the HTTPS redirect question, allowing both "
                             "HTTP and HTTPS.")
    parser.add_argument("-e", "--agree-tos", dest="eula", action="store_true",
                        help="Skip the end user license agreement screen.")
    parser.add_argument("-t", "--text", dest="use_curses", action="store_false",
                        help="Use the text output instead of the curses UI.")
    parser.add_argument("--test", dest="test", action="store_true",
                        help="Run in test mode.")

    args = parser.parse_args()

    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if args.use_curses:
        logger.addHandler(log.DialogHandler())
        displayer = display.NcursesDisplay()
    else:
        displayer = display.FileDisplay(sys.stdout)
    zope.component.provideUtility(displayer)

    installer = determine_installer()

    if args.revoke:
        revoc = revoker.Revoker(args.server, installer)
        revoc.list_certs_keys()
        sys.exit()

    if args.rollback > 0:
        rollback(installer, args.rollback)
        sys.exit()

    if args.view_config_changes:
        view_config_changes(installer)
        sys.exit()

    if not args.eula:
        display_eula()

    # Use the same object if possible
    if interfaces.IAuthenticator.providedBy(installer):
        auth = installer
    else:
        auth = determine_authenticator()

    domains = choose_names(installer) if args.domains is None else args.domains

    # Prepare for init of Client
    if args.privkey is None:
        privkey = client.init_key()
    else:
        privkey = client.Client.Key(args.privkey[0], args.privkey[1])

    acme = client.Client(args.server, privkey, auth, installer)

    # Validate the key and csr
    client.validate_key_csr(privkey)

    cert_file, chain_file = acme.obtain_certificate(domains)
    acme.deploy_certificate(domains, privkey, cert_file, chain_file)
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
    # This function adds all names
    # found within the config to self.names
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
    client.sanity_check_names(names)

    if not names:
        logging.fatal("No domain names were found in your installation")
        logging.fatal("Either specify which names you would like "
                      "letsencrypt to validate or add server names "
                      "to your virtual hosts")
        sys.exit(1)

    return names


# This should be controlled by commandline parameters
def determine_authenticator():
    """Returns a valid IAuthenticator."""
    try:
        if interfaces.IAuthenticator.implementedBy(
                configurator.ApacheConfigurator):
            return configurator.ApacheConfigurator()
    except errors.LetsEncryptConfiguratorError:
        logging.info("Unable to determine a way to authenticate the server")


def determine_installer():
    """Returns a valid installer if one exists."""
    try:
        if interfaces.IInstaller.implementedBy(
                configurator.ApacheConfigurator):
            return configurator.ApacheConfigurator()
    except errors.LetsEncryptConfiguratorError:
        logging.info("Unable to find a way to install the certificate.")


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


def rollback(installer, checkpoints):
    """Revert configuration the specified number of checkpoints.

    :param installer: Installer object
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    :param int checkpoints: Number of checkpoints to revert.

    """
    installer.rollback_checkpoints(checkpoints)
    installer.restart()


def view_config_changes(installer):
    """View checkpoints and associated configuration changes.

    :param installer: Installer object
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    """
    installer.view_config_changes()

if __name__ == "__main__":
    main()
