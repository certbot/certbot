#!/usr/bin/env python
"""Module to call certbot in test mode"""
from __future__ import absolute_import
from distutils.version import LooseVersion
import subprocess
import sys
import os

from certbot_integration_tests.utils import misc
from certbot_integration_tests.utils.constants import *


def certbot_test(certbot_args, directory_url, http_01_port, tls_alpn_01_port,
                 config_dir, workspace, force_renew=True):
    """
    Invoke the certbot executable available in PATH in a test context for the given args.
    The test context consists in running certbot in debug mode, with various flags suitable
    for tests (eg. no ssl check, customizable ACME challenge ports and config directory ...).
    This command captures stdout and returns it to the caller.
    :param list certbot_args: the arguments to pass to the certbot executable
    :param str directory_url: URL of the ACME directory server to use
    :param int http_01_port: port for the HTTP-01 challenges
    :param int tls_alpn_01_port: port for the TLS-ALPN-01 challenges
    :param str config_dir: certbot configuration directory to use
    :param str workspace: certbot current directory to use
    :param bool force_renew: set False to not force renew existing certificates (default: True)
    :return: stdout as string
    :rtype: str
    """
    command, env = _prepare_args_env(certbot_args, directory_url, http_01_port, tls_alpn_01_port,
                                     config_dir, workspace, force_renew)

    return subprocess.check_output(command, universal_newlines=True, cwd=workspace, env=env)


def _prepare_args_env(certbot_args, directory_url, http_01_port, tls_alpn_01_port,
                      config_dir, workspace, force_renew):
    new_environ = os.environ.copy()
    new_environ['TMPDIR'] = workspace

    additional_args = []
    if misc.get_certbot_version() >= LooseVersion('0.30.0'):
        additional_args.append('--no-random-sleep-on-renew')

    if force_renew:
        additional_args.append('--renew-by-default')

    command = [
        'certbot',
        '--server', directory_url,
        '--no-verify-ssl',
        '--http-01-port', str(http_01_port),
        '--https-port', str(tls_alpn_01_port),
        '--manual-public-ip-logging-ok',
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


def main():
    args = sys.argv[1:]

    # Default config is pebble
    directory_url = os.environ.get('SERVER', PEBBLE_DIRECTORY_URL)
    http_01_port = int(os.environ.get('HTTP_01_PORT', HTTP_01_PORT))
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
                                     config_dir, workspace, True)
    subprocess.check_call(command, universal_newlines=True, cwd=workspace, env=env)


if __name__ == '__main__':
    main()
