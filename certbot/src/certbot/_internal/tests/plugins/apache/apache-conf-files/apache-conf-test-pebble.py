#!/usr/bin/env python
"""
This executable script wraps the apache-conf-test bash script, in order to setup a pebble instance
before its execution. Directory URL is passed through the SERVER environment variable.
"""
import os
import subprocess
import sys

from certbot_integration_tests.utils import acme_server

SCRIPT_DIRNAME = os.path.dirname(__file__)


def main() -> int:
    args = sys.argv[1:]
    with acme_server.ACMEServer([], False) as acme_xdist:
        environ = os.environ.copy()
        environ['SERVER'] = acme_xdist['directory_url']
        command = [os.path.join(SCRIPT_DIRNAME, 'apache-conf-test')]
        command.extend(args)
        return subprocess.call(command, env=environ)


if __name__ == '__main__':
    sys.exit(main())
