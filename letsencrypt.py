#!/usr/bin/env python

# This file parses the command line and calls the appropriate functions

import getopt
import os
import sys

from trustify.client import client
from trustify.client import display

def main():
    # Check to make sure user is root
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run trustify.\n")
    # Parse options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["text", "test", "view-checkpoints", "privkey=", "csr=", "server=", "rollback=", "revoke"])
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
            from trustify.client import configurator, logger
            logger.setLogger(logger.FileLogger(sys.stdout))
            logger.setLogLevel(logger.INFO)
            config = configurator.Configurator()
            config.rollback_checkpoints(a)
            config.restart()
            sys.exit(0)
        elif o == "--view-checkpoints":
            from trustify.client import configurator, logger
            logger.setLogger(logger.FileLogger(sys.stdout))
            logger.setLogLevel(logger.INFO)
            config = configurator.Configurator()
            config.display_checkpoints()
            sys.exit(0)
        elif o == "--revoke":
            # Do Stuff
            flag_revoke = True

        elif o == "--test":
            #put any temporary tests in here
            continue

    if curses:
        display.setDisplay(display.NcursesDisplay())
    else:
        display.setDisplay(display.FileDisplay(sys.stdout))

    if not server:
        if "ACMESERVER" in os.environ:
            server = os.environ["ACMESERVER"]
        else:
            from trustify.client import logger
            logger.setLogger(logger.FileLogger(sys.stdout))
            logger.setLogLevel(logger.INFO)
            logger.warn("No ACME server specified. Please specify the ACMESERVER enviornment variable or the --server option")
            server = "54.183.196.250"

    c = client.Client(server, args, csr, privkey, curses)
    if flag_revoke:
        c.list_certs_keys()
    else:
        c.authenticate()

def usage():
    print "Available options: --text, --privkey=, --csr=, --server=, --rollback=, --view-checkpoints, --revoke"

if __name__ == "__main__":
    main()
