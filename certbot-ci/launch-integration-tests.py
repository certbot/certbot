#!/usr/bin/env python
"""
This module constitutes the CLI tool to launch integration tests.
It provides an argument parser and exposes relevant options for this kind of test.
Upon validation of a test campaign, the test environment will be setup, and the tests
launched through pytest.
"""
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

from acme.magic_typing import List, Tuple

CURRENT_DIR = os.path.dirname(__file__)
COVERAGE_THRESHOLD = 65


@contextlib.contextmanager
def certbot_ci_workspace():
    # type: () -> str
    """
    Generate a temporary workspace for certbot-ci, that will be the base tempdir for any
    call to the Python tempdir functions during the execution of this context.
    :return: The new base tempdir
    :rtype: str
    """
    original_tempdir = tempfile.tempdir
    try:
        tempfile.tempdir = os.path.join(tempfile.gettempdir(), 'certbot_ci_tmp')
        try:
            os.mkdir(tempfile.tempdir)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
        yield tempfile.tempdir
    finally:
        tempfile.tempdir = original_tempdir


def create_parser():
    # type: () -> argparse.ArgumentParser
    """
    Generate the parser of the CLI. It contains relevant options for integration tests.
    :return: An initialized ArgumentgParser instance
    :rtype: argparse.ArgumentParser
    """
    main_parser = argparse.ArgumentParser(description='Run the integration tests. '
                                                      'Docker and docker-compose needs to be '
                                                      'installed and available to current user. '
                                                      'Nginx also, for the nginx test campaign.')
    main_parser.add_argument('--acme-server', default='pebble-nonstrict',
                             choices=['boulder-v1', 'boulder-v2',
                                      'pebble-nonstrict', 'pebble-strict'],
                             help='select the ACME server to use (boulder-v1, boulder-v2, '
                                  'pebble-nonstrict or pebble-strict), '
                                  'defaulting to pebble-nonstrict')
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
    # type: (argparse.Namespace) -> Tuple[List[str], List[str]]
    """
    Construct the relevant pytest command and nodes for the options given from the CLI.
    :param object args: Namespace of the options processed from the CLI
    :return: A tuple of the command as an array, and a list of all pytest nodes names
    :rtype: (str[], str[])
    """
    nb_workers = multiprocessing.cpu_count() if args.numprocesses == 'auto' \
        else int(args.numprocesses)

    # Even if workers are equal to 1, we execute pytest using xdist (and so one node appart
    # master, to enforce coherency with multiple processing. And in no way we want the tests
    # to be executed as 'auto' without explicit user approval. Starting 16 boulders instances
    # without proper preparation will freeze the machine ...
    workers = ['gw{0}'.format(i) for i in range(nb_workers)]
    processes_cmd = ['--numprocesses', str(nb_workers)]

    # The idea here is to aggregate effective namespace to tests depending on the test
    # campaign that is selected. For instance, 'all' and 'certbot' will both load the
    # namespace corresponding to the certbot core tests.
    tests = []
    if args.campaign == 'all' or args.campaign == 'certbot':
        tests.append('certbot_integration_tests.certbot_tests')
    if args.campaign == 'all' or args.campaign == 'nginx':
        tests.append('certbot_integration_tests.nginx_tests')

    cover = ['--cov-report='] if args.coverage else []
    if cover and 'certbot_integration_tests.certbot_tests' in tests:
        cover.extend(['--cov=acme', '--cov=certbot'])
    if cover and 'certbot_integration_tests.nginx_tests' in tests:
        cover.append('--cov=certbot_nginx')

        try:
            subprocess.check_output(['nginx', '-v'], stderr=subprocess.STDOUT)
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
    # type: (argparse.Namespace) -> int
    """
    After a pytest execution, this function invoke coverage to build and print the coverage report.
    It will also check that coverage percentage is higher than threshold, returning a non zero
    status code otherwise.
    :param object args: Namespace of the options processed from the CLI
    :return: 0 if coverage is higher than threshold, 1 otherwise
    :rtype: int
    """
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
    # type: (List[str]) -> int
    """
    Main function of the CLI tool.
    Will:
        - expose the argument parser
        - process user input
        - check runtime compatiblity (Docker, docker-compose, Nginx)
        - generate the pytest command
        - create a temporary workspace and the persistent GIT repositories space
        - execute the pytest command in the temporary workspace
        - launch the coverage if needed
    :param cli_args: The arguments given by the CLI
    :return: 0 if the integration tests execution is considered as successful, 1 otherwise
    :rtype: int
    """
    main_parser = create_parser()
    args = main_parser.parse_args(cli_args)

    # Check for runtime compatiblity: some tools are required to be available in PATH
    try:
        subprocess.check_output(['docker', '-v'], stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, OSError):
        raise ValueError('Error: docker is required in PATH to launch the integration tests, '
                         'but is not installed or not available for current user.')

    try:
        subprocess.check_output(['docker-compose', '-v'], stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, OSError):
        raise ValueError('Error: docker-compose is required in PATH to launch the integration tests, '
                         'but is not installed or not available for current user.')

    # We will know, after the next command, how many workers need to be setup. Pytest command
    # will contain options that rely on several pytest plugins. Theses plugins should have been
    # installed through pip using the setup.py of certbot-ci project.
    (command, workers) = prepare_pytest_command(args)

    repositories_path = os.path.join(CURRENT_DIR, '.ci_assets/integration_tests')
    try:
        os.makedirs(repositories_path)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    # By calling certbot_ci_workspace, the tempfile.tempdir value of standard tempfile module is
    # modified for the context execution time, to ensure that any temporary assets will be created
    # under the cerbot-ci workspace.
    with certbot_ci_workspace():
        acme_config = {}
        # Prepare the acme config server. Data is specific to an acme type. Module
        # utils.acme_server will handle theses specifics.
        if 'pebble' in args.acme_server:
            acme_config['type'] = 'pebble'
            acme_config['option'] = 'strict' if 'strict' in args.acme_server else 'nonstrict'
        else:
            acme_config['type'] = 'boulder'
            acme_config['option'] = 'v1' if 'v1' in args.acme_server else 'v2'
        # By calling setup_acme_server we ensure that all necessary acme servers instances will be
        # fully started once the context is entered. This runtime is reflected by the acme_xdist
        # provided by the contextmanager.
        with acme.setup_acme_server(acme_config, workers, repositories_path) as acme_xdist:
            os.environ['CERTBOT_ACME_TYPE'] = args.acme_server
            os.environ['CERTBOT_ACME_XDIST'] = json.dumps(acme_xdist)
            print('ACME xdist config:\n{0}'.format(os.environ['CERTBOT_ACME_XDIST']))
            # We contain the pytest execution in the context of the certbot-ci workspace, to ensure
            # that any temporary asset of pytest will be written in this workspace, and can be
            # properly cleaned up.
            with misc.execute_in_given_cwd(os.path.join(CURRENT_DIR, 'certbot_integration_tests')):
                # Chained call of the pytest.main function, that execute effectively pytest, and
                # process_coverage to run coverage report. If any of them fail, exit code should
                # not be 0, to allow any caller to fail correctly (like env tox invocation)
                return max(pytest.main(command), process_coverage(args))


if __name__ == '__main__':
    sys.exit(main())
