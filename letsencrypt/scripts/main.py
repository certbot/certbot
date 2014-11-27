#!/usr/bin/env python
"""Parse command line and call the appropriate functions."""
import argparse
import os
import sys

from letsencrypt.client import apache_configurator
from letsencrypt.client import CONFIG
from letsencrypt.client import client
from letsencrypt.client import display
from letsencrypt.client import logger

logger.setLogger(logger.FileLogger(sys.stdout))
logger.setLogLevel(logger.INFO)


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
    parser.add_argument("-p", "--privkey", dest="privkey",
                        help="Path to the private key file for certificate "
                             "generation.")
    parser.add_argument("-c", "--csr", dest="csr",
                        help="Path to the certificate signing request file "
                             "corresponding to the private key file. The "
                             "private key file argument is required if this "
                             "argument is specified.")
    parser.add_argument("-b", "--rollback", dest="rollback", type=int,
                        default=0,
                        help="Revert configuration <ROLLBACK> number of "
                             "checkpoints.")
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
    parser.add_argument("-t", "--text", dest="curses", action="store_false",
                        help="Use the text output instead of the curses UI.")
    parser.add_argument("--test", dest="test", action="store_true",
                        help="Run in test mode.")

    args = parser.parse_args()

    # Enforce '--privkey' is set along with '--csr'.
    if args.csr and not args.privkey:
        parser.error("private key file (--privkey) must be specified along{} "
                     "with the certificate signing request file (--csr)"
                     .format(os.linesep))

    if args.curses:
        display.set_display(display.NcursesDisplay())
    else:
        display.set_display(display.FileDisplay(sys.stdout))

    if args.rollback > 0:
        rollback(apache_configurator.ApacheConfigurator(), args.rollback)
        sys.exit()

    if args.view_checkpoints:
        view_checkpoints(apache_configurator.ApacheConfigurator())
        sys.exit()

    server = args.server is None and CONFIG.ACME_SERVER or args.server

    acme = client.Client(server, args.csr, args.privkey, args.curses)
    if args.revoke:
        acme.list_certs_keys()
    else:
        acme.authenticate(args.domains, args.redirect, args.eula)


def rollback(config, checkpoints):
    """Revert configuration the specified number of checkpoints.

    :param config: Configurator object
    :type config: ApacheConfigurator

    :param checkpoints: Number of checkpoints to revert.
    :type checkpoints: int

    """
    config.rollback_checkpoints(checkpoints)
    config.restart()


def view_checkpoints(config):
    """View checkpoints and associated configuration changes.

    :param config: Configurator object
    :type config: ApacheConfigurator

    """
    config.display_checkpoints()


if __name__ == "__main__":
    main()
