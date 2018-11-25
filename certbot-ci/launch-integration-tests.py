#!/usr/bin/env python
import argparse
import sys
import pytest
import os

from certbot_integration_tests.utils import acme

CURRENT_DIR = os.path.dirname(__file__)


def create_parser():
    main_parser = argparse.ArgumentParser(description='Run the integration tests')
    main_parser.add_argument('--acme-server', default='boulder-v2',
                             choices=['boulder-v1', 'boulder-v2', 'pebble-nonstrict', 'pebble-strict'],
                             help='select the ACME server to use (boulder-v1, boulder-v2, '
                                  'pebble-nonstrict or pebble-strict), defaulting to boulder-v2')
    main_parser.add_argument('--campaign', choices=['all', 'certbot', 'nginx'], default='certbot',
                             help='select the test campaign to run (all, certbot or nginx),'
                                  'defaulting to certbot')
    main_parser.add_argument('--coverage', action='store_true',
                             help='run code coverage during integration tests')

    return main_parser


def main(cli_args=sys.argv[1:]):
    main_parser = create_parser()
    args = main_parser.parse_args(cli_args)

    tests = []
    if args.campaign == 'all' or args.campaign == 'certbot':
        tests.append('certbot_integration_tests.certbot_test')
    if args.campaign == 'all' or args.campaign == 'nginx':
        tests.append('certbot_integration_tests.nginx_test')

    cover = ['--cov', 'acme', '--cov', 'certbot'] if args.coverage else []

    with acme.setup_acme_server(args.acme_server):
        os.environ['CERTBOT_INTEGRATION'] = args.acme_server
        current_cwd = os.getcwd()
        try:
            os.chdir(os.path.join(CURRENT_DIR, 'certbot_integration_tests'))
            exit_code = pytest.main(['--pyargs', '--numprocesses', '1', *cover, *tests])
        finally:
            os.chdir(current_cwd)

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
