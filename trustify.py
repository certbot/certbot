#!/usr/bin/env python

# This file parses the command line and calls the appropriate functions

import getopt
import os
import sys

from trustify.client import client

def main():
    # Check to make sure user is root
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run trustify.\n")
    # Parse options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["text", "view-checkpoints", "privkey=", "csr=", "server=", "rollback="])
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
            from trustify.client import configurator
            config = configurator.Configurator()
            config.recover_checkpoint(a)
            continue
        elif o == "--view-checkpoints":
            from trustify.client import configurator
            config = configurator.Configurator()
            config.display_checkpoints()
            sys.exit(0)
            
    if not server:
        if "CHOCOLATESERVER" in os.environ:
            server = os.environ["CHOCOLATESERVER"]
        else:
            server = "ca.theobroma.info"
    
    c = client.Client(server, args, csr, privkey, curses)
    c.authenticate()

def usage():
    print "Available options: --text, --privkey=, --csr=, --server=, --rollback=, --view-checkpoints"

if __name__ == "__main__":
    main()
