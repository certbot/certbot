#!/usr/bin/env python
"""Parse command line and call the appropriate functions."""
import getopt
import os
import sys

from letsencrypt.client import apache_configurator
from letsencrypt.client import CONFIG
from letsencrypt.client import client
from letsencrypt.client import display
from letsencrypt.client import logger


def main():
    # Check to make sure user is root
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run letsencrypt.\n")
    # Parse options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["text", "test",
                                                      "view-checkpoints",
                                                      "privkey=", "csr=",
                                                      "server=", "rollback=",
                                                      "revoke", "agree-eula",
                                                      "redirect",
                                                      "no-redirect",
                                                      "help"])
    except getopt.GetoptError as err:
        # print help info and exit
        print str(err)
        usage()
        sys.exit(2)

    server = None
    csr = None
    privkey = None
    curses = True
    names = args
    flag_revoke = False
    redirect = None
    eula = False

    for o, a in opts:
        if o == "--text":
            curses = False
        elif o == "--csr":
            csr = a
        elif o == "--privkey":
            privkey = a
        elif o == "--server":
            server = a
        elif o == "--rollback":
            logger.setLogger(logger.FileLogger(sys.stdout))
            logger.setLogLevel(logger.INFO)
            config = apache_configurator.ApacheConfigurator()
            config.rollback_checkpoints(a)
            config.restart()
            sys.exit(0)
        elif o == "--view-checkpoints":
            logger.setLogger(logger.FileLogger(sys.stdout))
            logger.setLogLevel(logger.INFO)
            config = apache_configurator.ApacheConfigurator()
            config.display_checkpoints()
            sys.exit(0)
        elif o == "--revoke":
            # Do Stuff
            flag_revoke = True
        elif o == "--redirect":
            redirect = True
        elif o == "--no-redirect":
            redirect = False
        elif o == "--agree-eula":
            eula = True
        elif o == "--help":
            print_options()
        elif o == "--test":
            #put any temporary tests in here
            continue

    if curses:
        display.set_display(display.NcursesDisplay())
    else:
        display.set_display(display.FileDisplay(sys.stdout))

    if not server:
        server = CONFIG.ACME_SERVER

    c = client.Client(server, csr, privkey, curses)
    if flag_revoke:
        c.list_certs_keys()
    else:
        c.authenticate(args, redirect, eula)

def usage():
    s = "Available options: --text, --privkey=, --csr=, --server=, "
    s += "--rollback=, --view-checkpoints, --revoke, --agree-eula, --redirect,"
    s += " --no-redirect, --help"
    print s

def print_options():
    print "\nsudo ./letsencrypt.py (default authentication mode using pythondialog)"
    options = [ "privkey= (specify privatekey file to use to generate the certificate)",
                "csr= (Use a specific CSR. If this is specified, privkey " +
                "must also be specified with the correct private key for the CSR)",
                "server (list the ACME CA server address)",
                "revoke (revoke a certificate)",
                "view-checkpoints (Used to view available checkpoints and " +
                "see what configuration changes have been made)",
                "rollback=X (Revert the configuration X number of checkpoints)",
                "redirect (Automatically redirect all HTTP traffic to " +
                "HTTPS for the newly authenticated vhost)",
                "no-redirect (Skip the HTTPS redirect question, " +
                "allowing both HTTP and HTTPS)",
                "agree-eula (Skip the end user agreement screen)" ]
    for o in options:
        print "    --%s" % o
    sys.exit(0)

if __name__ == "__main__":
    main()
