#!/usr/bin/env python
from __future__ import absolute_import
from distutils.version import LooseVersion
import subprocess
import sys
import os

from certbot_integration_tests.utils import misc


def certbot_test(certbot_args, directory_url, http_01_port, tls_alpn_01_port,
                 config_dir, workspace, force_renew, capture_stdout):
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

    subprocess_call = subprocess.check_output if capture_stdout else subprocess.check_call

    print('--> Invoke command:\n=====\n{0}\n====='.format(subprocess.list2cmdline(command)))
    return subprocess_call(command, universal_newlines=True,
                           cwd=workspace, env=new_environ)


def main():
    args = sys.argv[1:]

    # Default config is pebble
    directory_url = os.environ.get('SERVER', 'https://localhost:14000/dir')
    http_01_port = int(os.environ.get('HTTP_01_PORT', '5002'))
    tls_alpn_01_port = int(os.environ.get('TLS_ALPN_01_PORT', '5001'))

    # Execution of certbot in a self-contained workspace
    workspace = os.environ.get('WORKSPACE', os.path.join(os.getcwd(), '.certbot_test_workspace'))
    if not os.path.exists(workspace):
        print('--> Create a workspace for certbot_test: {0}'.format(workspace))
        os.mkdir(workspace)
    else:
        print('--> Use an existing workspace for certbot_test: {0}'.format(workspace))
    config_dir = os.path.join(workspace, 'conf')

    certbot_test(args, directory_url, http_01_port, tls_alpn_01_port,
                 config_dir, workspace, True, False)


if __name__ == '__main__':
    main()
