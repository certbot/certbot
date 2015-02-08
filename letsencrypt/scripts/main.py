#!/usr/bin/env python
"""Parse command line and call the appropriate functions.

..todo:: Sanity check all input.  Be sure to avoid shell code etc...

"""
import argparse
import logging
import os
import sys

import zope.component
import zope.interface

import letsencrypt
from letsencrypt.client import CONFIG
from letsencrypt.client import client
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util
from letsencrypt.client import log
from letsencrypt.client.display import display_util
from letsencrypt.client.display import ops


def main():  # pylint: disable=too-many-statements,too-many-branches
    """Command line argument parsing and main script execution."""
    parser = argparse.ArgumentParser(
        description="letsencrypt client %s" % letsencrypt.__version__)

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
    parser.add_argument("-B", "--keysize", dest="key_size", type=int,
                        default=CONFIG.RSA_KEY_SIZE, metavar="N",
                        help="RSA key shall be sized N bits. [%(default)d]")
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

    # note: arg parser internally handles --help (and exits afterwards)
    args = parser.parse_args()

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
        displayer = display_util.NcursesDisplay()
    else:
        displayer = display_util.FileDisplay(sys.stdout)
    zope.component.provideUtility(displayer)

    if args.view_config_changes:
        client.view_config_changes()
        sys.exit()

    if args.revoke:
        client.revoke(args.server)
        sys.exit()

    if args.rollback > 0:
        client.rollback(args.rollback)
        sys.exit()

    if not args.eula:
        display_eula()

    # Make sure we actually get an installer that is functioning properly
    # before we begin to try to use it.
    try:
        installer = client.determine_authenticator()
    except errors.LetsEncryptMisconfigurationError as err:
        logging.fatal("Please fix your configuration before proceeding.{0}"
                      "The Authenticator exited with the following message: "
                      "{1}".format(os.linesep, err))
        sys.exit(1)

    # Use the same object if possible
    if interfaces.IAuthenticator.providedBy(installer):  # pylint: disable=no-member
        auth = installer
    else:
        auth = client.determine_authenticator()

    domains = ops.choose_names(installer) if args.domains is None else args.domains

    # Prepare for init of Client
    if args.privkey is None:
        privkey = client.init_key(args.key_size)
    else:
        privkey = le_util.Key(args.privkey[0], args.privkey[1])

    acme = client.Client(args.server, privkey, auth, installer)

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
    with open("EULA") as eula_file:
        if not zope.component.getUtility(interfaces.IDisplay).yesno(
                eula_file.read(), "Agree", "Cancel"):
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


if __name__ == "__main__":
    main()
