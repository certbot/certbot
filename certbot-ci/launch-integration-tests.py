#!/usr/bin/env python
import argparse
import sys
import pytest
import os
import contextlib
import json
import tempfile
import errno
import multiprocessing
import subprocess

import coverage

from certbot_integration_tests.utils import acme, misc

CURRENT_DIR = os.path.dirname(__file__)
COVERAGE_THRESHOLD = 75


@contextlib.contextmanager
def certbot_ci_workspace():
    original_tempdir = tempfile.tempdir
    try:
        tempfile.tempdir = os.path.join(tempfile.gettempdir(), 'certbot_ci_tmp')
        try:
            os.mkdir(tempfile.tempdir)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
        yield
    finally:
        tempfile.tempdir = original_tempdir


def create_parser():
    main_parser = argparse.ArgumentParser(description='Run the integration tests. '
                                                      'Docker and docker-compose needs to be '
                                                      'installed and available to current user. '
                                                      'Nginx also, for the nginx test campaign.')
    main_parser.add_argument('--acme-server', default='pebble-nonstrict',
                             choices=['boulder-v1', 'boulder-v2',
                                      'pebble-nonstrict', 'pebble-strict'],
                             help='select the ACME server to use (boulder-v1, boulder-v2, '
                                  'pebble-nonstrict or pebble-strict), defaulting to pebble-nonstrict')
    main_parser.add_argument('--campaign', choices=['all', 'certbot', 'nginx'], default='certbot',
                             help='select the test campaign to run (all, certbot or nginx),'
                                  'defaulting to certbot')
    main_parser.add_argument('--coverage', action='store_true',
                             help='run code coverage during integration tests')
    main_parser.add_argument('--no-capture', action='store_true',
                             help='disable output capturing while running tests')
    main_parser.add_argument('--numprocesses', metavar='N/auto', default=1,
                             help='number of parallel executions (or \'auto\' to scale '
                                  'up to all CPUs available), defaulting to 1')

    return main_parser


def prepare_pytest_command(args):
    nb_workers = multiprocessing.cpu_count() if args.numprocesses == 'auto' \
        else int(args.numprocesses)

    workers = ['gw{0}'.format(i) for i in range(nb_workers)] \
        if nb_workers > 1 else ['master']
    processes_cmd = ['--numprocesses', str(nb_workers)] \
        if nb_workers > 1 else []

    tests = []
    if args.campaign == 'all' or args.campaign == 'certbot':
        tests.append('certbot_integration_tests.certbot_tests')
    if args.campaign == 'all' or args.campaign == 'nginx':
        tests.append('certbot_integration_tests.nginx_tests')

    cover = ['--cov-report='] if args.coverage else []
    if cover and 'certbot_integration_tests.cerbot_tests' in tests:
        cover.extend(['--cov=acme', '--cov=certbot'])
    if cover and 'certbot_integration_tests.nginx_tests' in tests:
        cover.append('--cov=certbot_nginx')

        try:
            subprocess.check_call(['nginx', '-v'], stdout=acme.FNULL, stderr=acme.FNULL)
        except (subprocess.CalledProcessError, OSError):
            raise ValueError('Error: nginx is required in PATH to launch the nginx integration tests, '
                             'but is not installed or not available for current user.')

    capture = ['-s'] if args.no_capture else []

    command = ['--pyargs', '-W', 'ignore:Unverified HTTPS request', '--reruns', '2']
    command.extend(processes_cmd)
    command.extend(capture)
    command.extend(cover)
    command.extend(tests)

    return command, workers


def process_coverage(args):
    if args.coverage:
        cov = coverage.Coverage()
        cov.load()
        covered = cov.report(show_missing=True)

        if covered < COVERAGE_THRESHOLD:
            sys.stderr.write('Current coverage ({0}) is under threshold ({1})!{2}'
                             .format(round(covered, 2),
                                     COVERAGE_THRESHOLD, os.linesep))

            return 1

    return 0


def main(cli_args=sys.argv[1:]):
    main_parser = create_parser()
    args = main_parser.parse_args(cli_args)

    try:
        subprocess.check_call(['docker', '-v'], stdout=acme.FNULL, stderr=acme.FNULL)
    except (subprocess.CalledProcessError, OSError):
        raise ValueError('Error: docker is required in PATH to launch the integration tests, '
                         'but is not installed or not available for current user.')

    try:
        subprocess.check_call(['docker-compose', '-v'], stdout=acme.FNULL, stderr=acme.FNULL)
    except (subprocess.CalledProcessError, OSError):
        raise ValueError('Error: docker-compose is required in PATH to launch the integration tests, '
                         'but is not installed or not available for current user.')

    (command, workers) = prepare_pytest_command(args)

    repositories_path = os.path.join(CURRENT_DIR, '.ci_assets/integration_tests')
    try:
        os.makedirs(repositories_path)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    with certbot_ci_workspace():
        with acme.setup_acme_server(args.acme_server, workers, repositories_path) as acme_xdist:
            os.environ['CERTBOT_ACME_TYPE'] = args.acme_server
            os.environ['CERTBOT_ACME_XDIST'] = json.dumps(acme_xdist)
            with misc.execute_in_given_cwd(os.path.join(CURRENT_DIR, 'certbot_integration_tests')):
                return max(pytest.main(command), process_coverage(args))


if __name__ == '__main__':
    sys.exit(main())
