#!/usr/bin/env python
import argparse
import sys
import pytest
import os
import contextlib

import coverage

from certbot_integration_tests.utils import acme

CURRENT_DIR = os.path.dirname(__file__)
COVERAGE_THRESHOLD = 75


@contextlib.contextmanager
def execute_in_given_cwd(cwd):
    current_cwd = os.getcwd()
    try:
        os.chdir(cwd)
        yield
    finally:
        os.chdir(current_cwd)


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
    main_parser.add_argument('--no-capture', action='store_true',
                             help='disable output capturing while running tests')

    return main_parser


def main(cli_args=sys.argv[1:]):
    main_parser = create_parser()
    args = main_parser.parse_args(cli_args)

    tests = []
    if args.campaign == 'all' or args.campaign == 'certbot':
        tests.append('certbot_integration_tests.certbot_test')
    if args.campaign == 'all' or args.campaign == 'nginx':
        tests.append('certbot_integration_tests.nginx_test')

    cover = ['--cov-report=', '--cov=acme', '--cov=certbot'] if args.coverage else []

    capture = ['-s'] if args.no_capture else []

    command = ['--pyargs']
    command.extend(capture)
    command.extend(cover)
    command.extend(tests)

    with acme.setup_acme_server(args.acme_server):
        os.environ['CERTBOT_INTEGRATION'] = args.acme_server
        with execute_in_given_cwd(os.path.join(CURRENT_DIR, 'certbot_integration_tests')):
            exit_code = pytest.main(command)

            if args.coverage:
                cov = coverage.Coverage()
                cov.load()
                covered = cov.report(show_missing=True)

                if covered < COVERAGE_THRESHOLD:
                    sys.stderr.write('Current coverage ({0}) is under threshold ({1})!{2}'
                                     .format(round(covered, 2), COVERAGE_THRESHOLD, os.linesep))

                    exit_code = max(exit_code, 1)

            return exit_code


if __name__ == '__main__':
    sys.exit(main())
