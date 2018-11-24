import os
import tempfile
import sys
import stat
import subprocess

import pytest

from certbot_integration_tests.utils import misc


@pytest.fixture
def certbot_test_no_force_renew(workspace, config_dir, acme_url, http_01_port, tls_sni_01_port, capsys):
    def func(args):
        command = [
            'certbot', '--server', acme_url, '--no-verify-ssl', '--tls-sni-01-port',
            str(tls_sni_01_port), '--http-01-port', str(http_01_port),
            '--manual-public-ip-logging-ok', '--config-dir', config_dir, '--work-dir',
            os.path.join(workspace, 'work'), '--logs-dir', os.path.join(workspace, 'logs'),
            '--non-interactive', '--no-redirect', '--agree-tos',
            '--register-unsafely-without-email', '--debug', '-vv'
        ]

        command.extend(args)

        # Normally during a test with capture enabled, stdin is set to null
        # and stdin.isatty returns false.
        # This non-interactive situation would lead certbot renew operations to wait a random
        # number of minutes before executing, and we obviously want to avoid that during tests.
        # So we get real stdin without capture to be used in the subprocess call.
        with capsys.disabled():
            real_stdin = sys.stdin

        print('Invoke command:\n{0}'.format(subprocess.list2cmdline(command)))
        return subprocess.check_output(command, universal_newlines=True, stdin=real_stdin)

    return func


@pytest.fixture
def certbot_test(config_dir, acme_url, http_01_port, tls_sni_01_port):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        return certbot_test_no_force_renew(command)

    return func


@pytest.fixture
def common_no_force_renew(certbot_test_no_force_renew):
    def func(args):
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        return certbot_test_no_force_renew(command)

    return func


@pytest.fixture
def common(common_no_force_renew):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        return common_no_force_renew(command)

    return func


@pytest.fixture
def http_01_server(http_01_port):
    with misc.create_tcp_server(http_01_port) as webroot:
        yield webroot


@pytest.fixture
def tls_sni_01_server(tls_sni_01_port):
    with misc.create_tcp_server(tls_sni_01_port) as webroot:
        yield webroot


@pytest.fixture
def hook_probe():
    probe = tempfile.mkstemp()
    try:
        yield probe[1]
    finally:
        os.unlink(probe[1])


@pytest.fixture
def generate_test_hooks(renewal_hooks_dirs, hook_probe):
    if sys.platform == 'win32':
        extension = 'bat'
    else:
        extension = 'sh'
    try:
        renewal_dir_pre_hook = os.path.join(renewal_hooks_dirs[0], 'hook.{0}'.format(extension))
        renewal_dir_deploy_hook = os.path.join(renewal_hooks_dirs[1], 'hook.{0}'.format(extension))
        renewal_dir_post_hook = os.path.join(renewal_hooks_dirs[2], 'hook.{0}'.format(extension))

        for hook_dir in renewal_hooks_dirs:
            os.makedirs(hook_dir)
            hook_path = os.path.join(hook_dir, 'hook.{0}'.format(extension))
            if extension == 'sh':
                data = '''\
#!/bin/bash -xe
if [ "$0" ] == "{0}" ]; then
    if [ -z "$RENEWED_DOMAINS" -o -z "$RENEWED_LINEAGE" ]; then
        echo "Environment variables not properly set!" >&2
        exit 1
    fi
fi
echo $(basename $(dirname "$0")) >> "{1}"\
'''.format(renewal_dir_deploy_hook, hook_probe)
            else:
                data = '''\

'''
            with open(hook_path, 'w') as file:
                file.write(data)
            os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IEXEC)

            yield {
                'renewal_hooks_execution_probe': hook_probe,
                'renewal_dir_pre_hook': renewal_dir_pre_hook,
                'renewal_dir_deploy_hook': renewal_dir_deploy_hook,
                'renewal_dir_post_hook': renewal_dir_post_hook
            }
    finally:
        for hook_dir in renewal_hooks_dirs:
            os.unlink(os.path.join(hook_dir, 'hook.{0}'.format(extension)))
