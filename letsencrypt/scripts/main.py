#!/usr/bin/env python
"""Parse command line and call the appropriate functions."""
import argparse
import logging
import os
import sys

from letsencrypt.client import CONFIG
from letsencrypt.client import client
from letsencrypt.client import display
from letsencrypt.client import interfaces
from letsencrypt.client import errors
from letsencrypt.client import log

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
                        help="The ACME CA server address.")
    parser.add_argument("-p", "--privkey", dest="privkey", type=read_file,
                        help="Path to the private key file for certificate "
                             "generation.")
    parser.add_argument("-c", "--csr", dest="csr", type=read_file,
                        help="Path to the certificate signing request file "
                             "corresponding to the private key file. The "
                             "private key file argument is required if this "
                             "argument is specified.")
    parser.add_argument("-b", "--rollback", dest="rollback", type=int,
                        default=0, metavar="N",
                        help="Revert configuration N number of checkpoints.")
    parser.add_argument("-k", "--revoke", dest="revoke", action="store_true",
                        help="Revoke a certificate.")
    parser.add_argument("-v", "--view-checkpoints", dest="view_checkpoints",
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
    parser.add_argument("-e", "--agree-eula", dest="eula", action="store_true",
                        help="Skip the end user license agreement screen.")
    parser.add_argument("-t", "--text", dest="use_curses", action="store_false",
                        help="Use the text output instead of the curses UI.")
    parser.add_argument("--test", dest="test", action="store_true",
                        help="Run in test mode.")

    args = parser.parse_args()

    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)  # TODO: --log
    if args.use_curses:
        logger.addHandler(log.DialogHandler())

    # Enforce '--privkey' is set along with '--csr'.
    if args.csr and not args.privkey:
        parser.error("private key file (--privkey) must be specified along{0} "
                     "with the certificate signing request file (--csr)"
                     .format(os.linesep))

    if args.use_curses:
        display.set_display(display.NcursesDisplay())
    else:
        display.set_display(display.FileDisplay(sys.stdout))

    if args.rollback > 0:
        rollback(configurator.ApacheConfigurator(), args.rollback)
        sys.exit()

    if args.view_checkpoints:
        view_checkpoints(configurator.ApacheConfigurator())
        sys.exit()

    server = args.server is None and CONFIG.ACME_SERVER or args.server

    if not args.eula:
        display_eula()

    auth = determine_authenticator()

    # Use the same object if possible
    if interfaces.IInstaller.providedBy(auth):
        installer = auth
    else:
        installer = determine_installer()

    domains = choose_names(installer) if args.domains is None else args.domains

    # Prepare for init of Client
    if args.privkey is None:
        privkey = client.init_key()
    else:
        privkey = client.Client.Key(args.privkey[0], args.privkey[1])
    if args.csr is None:
        csr = client.init_csr(privkey, domains)
    else:
        csr = client.csr_pem_to_der(
            client.Client.CSR(args.csr[0], args.csr[1], "pem"))

    acme = client.Client(server, domains, privkey, auth, installer)
    if args.revoke:
        acme.list_certs_keys()
    else:
        # Validate the key and csr
        client.validate_key_csr(privkey, csr, domains)

        cert_file, chain_file = acme.obtain_certificate(csr)
        vhost = acme.deploy_certificate(privkey, cert_file, chain_file)
        acme.optimize_config(vhost, args.redirect)


def display_eula():
    """Displays the end user agreement."""
    with open('EULA') as eula_file:
        if not display.generic_yesno(
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
    code, names = display.filter_names(get_all_names(installer))
    if code == display.OK and names:
        # TODO: Allow multiple names once it is setup
        return [names[0]]
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
    """Returns a valid authenticator."""
    try:
        return configurator.ApacheConfigurator()
    except errors.LetsEncryptConfiguratorError:
        logging.info("Unable to find a way to authenticate.")


def determine_installer():
    """Returns a valid installer if one exists."""
    try:
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
        return filename, file(filename, 'rU').read()
    except IOError as exc:
        raise argparse.ArgumentTypeError(exc.strerror)


def rollback(config, checkpoints):
    """Revert configuration the specified number of checkpoints.

    :param config: Configurator object
    :type config: :class:`ApacheConfigurator`

    :param int checkpoints: Number of checkpoints to revert.

    """
    config.rollback_checkpoints(checkpoints)
    config.restart()


def view_checkpoints(config):
    """View checkpoints and associated configuration changes.

    :param config: Configurator object
    :type config: :class:`ApacheConfigurator`

    """
    config.display_checkpoints()

if __name__ == "__main__":
    main()
