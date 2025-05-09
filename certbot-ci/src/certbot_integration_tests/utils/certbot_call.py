#!/usr/bin/env python
"""Module to call certbot in test mode"""

import os
import subprocess
import sys
from typing import Dict
from typing import List
from typing import Tuple

import certbot_integration_tests
# pylint: disable=wildcard-import,unused-wildcard-import
from certbot_integration_tests.utils.constants import *


def certbot_test(certbot_args: List[str], directory_url: str, http_01_port: int,
                 tls_alpn_01_port: int, config_dir: str, workspace: str,
                 force_renew: bool = True) -> Tuple[str, str]:
    """
    Invoke the certbot executable available in PATH in a test context for the given args.
    The test context consists in running certbot in debug mode, with various flags suitable
    for tests (eg. no ssl check, customizable ACME challenge ports and config directory ...).
    This command captures both stdout and stderr and returns it to the caller.
    :param list certbot_args: the arguments to pass to the certbot executable
    :param str directory_url: URL of the ACME directory server to use
    :param int http_01_port: port for the HTTP-01 challenges
    :param int tls_alpn_01_port: port for the TLS-ALPN-01 challenges
    :param str config_dir: certbot configuration directory to use
    :param str workspace: certbot current directory to use
    :param bool force_renew: set False to not force renew existing certificates (default: True)
    :return: stdout and stderr as strings
    :rtype: `tuple` of `str`
    """
    command, env = _prepare_args_env(certbot_args, directory_url, http_01_port, tls_alpn_01_port,
                                     config_dir, workspace, force_renew)

    proc = subprocess.run(command, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False, universal_newlines=True,
                          cwd=workspace, env=env)
    print('--> Certbot log output was:')
    print(proc.stderr)
    proc.check_returncode()
    return proc.stdout, proc.stderr


def _prepare_environ(workspace: str) -> Dict[str, str]:
    # pylint: disable=missing-function-docstring

    new_environ = os.environ.copy()
    new_environ['TMPDIR'] = workspace

    # So, pytest is nice, and a little too nice for our usage.
    # In order to help user to call seamlessly any piece of python code without requiring to
    # install it as a full-fledged Python package for instance, it may inject the path
    # to the test files into the PYTHONPATH. This allows the python interpreter to import
    # as modules any python file available at this path.
    # See https://docs.pytest.org/en/3.2.5/pythonpath.html for the explanation and description.
    # However this behavior is not good in integration tests, in particular the nginx oldest ones.
    # Indeed during these kind of tests certbot is installed as a transitive dependency to
    # certbot-nginx. Here is the trick: this certbot version is not necessarily the same as
    # the certbot codebase lying in current working directory. For instance in oldest tests
    # certbot==0.36.0 may be installed while the codebase corresponds to certbot==0.37.0.dev0.
    # Then during a pytest run, PYTHONPATH contains the path to the Certbot codebase, so invoking
    # certbot will import the modules from the codebase (0.37.0.dev0), not from the
    # required/installed version (0.36.0).
    # This will lead to funny and totally incomprehensible errors. To avoid that, we ensure that
    # if PYTHONPATH is set, it does not contain the path to the root of the codebase.
    if new_environ.get('PYTHONPATH'):
        # certbot_integration_tests.__file__ is:
        # '/path/to/certbot/certbot-ci/src/certbot_integration_tests/__init__.pyc'
        # ... and we want '/path/to/certbot'
        certbot_root = os.path.dirname(os.path.dirname(
            os.path.dirname(certbot_integration_tests.__file__))
        )
        python_paths = [
            path for path in new_environ['PYTHONPATH'].split(':')
            if path != certbot_root
        ]
        new_environ['PYTHONPATH'] = ':'.join(python_paths)

    return new_environ


def _prepare_args_env(certbot_args: List[str], directory_url: str, http_01_port: int,
                      tls_alpn_01_port: int, config_dir: str, workspace: str,
                      force_renew: bool) -> Tuple[List[str], Dict[str, str]]:

    new_environ = _prepare_environ(workspace)
    additional_args = ['--no-random-sleep-on-renew']
    if force_renew:
        additional_args.append('--renew-by-default')

    command = [
        'certbot',
        '--server', directory_url,
        '--no-verify-ssl',
        '--http-01-port', str(http_01_port),
        '--https-port', str(tls_alpn_01_port),
        '--config-dir', config_dir,
        '--work-dir', os.path.join(workspace, 'work'),
        '--logs-dir', os.path.join(workspace, 'logs'),
        '--non-interactive',
        '--no-redirect',
        '--agree-tos',
        '--register-unsafely-without-email',
        '--debug',
        '-vv'
    ]

    command.extend(certbot_args)
    command.extend(additional_args)

    print('--> Invoke command:\n=====\n{0}\n====='.format(subprocess.list2cmdline(command)))

    return command, new_environ


def main() -> None:
    # pylint: disable=missing-function-docstring
    args = sys.argv[1:]

    # Default config is pebble
    directory_url = os.environ.get('SERVER', PEBBLE_DIRECTORY_URL)
    http_01_port = int(os.environ.get('HTTP_01_PORT', DEFAULT_HTTP_01_PORT))
    tls_alpn_01_port = int(os.environ.get('TLS_ALPN_01_PORT', TLS_ALPN_01_PORT))

    # Execution of certbot in a self-contained workspace
    workspace = os.environ.get('WORKSPACE', os.path.join(os.getcwd(), '.certbot_test_workspace'))
    if not os.path.exists(workspace):
        print('--> Creating a workspace for certbot_test: {0}'.format(workspace))
        os.mkdir(workspace)
    else:
        print('--> Using an existing workspace for certbot_test: {0}'.format(workspace))
    config_dir = os.path.join(workspace, 'conf')

    # Invoke certbot in test mode, without capturing output so users see directly the outcome.
    command, env = _prepare_args_env(args, directory_url, http_01_port, tls_alpn_01_port,
                                     config_dir, workspace, False)
    subprocess.check_call(command, universal_newlines=True, cwd=workspace, env=env)


if __name__ == '__main__':
    main()
