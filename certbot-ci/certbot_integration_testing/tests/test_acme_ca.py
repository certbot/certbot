import ssl
import multiprocessing
import tempfile
import subprocess
import os
import sys
import stat

import pytest
from six.moves.urllib.request import urlopen
from six.moves import socketserver
from six.moves import SimpleHTTPServer


@pytest.fixture(scope='module')
def common_no_force_renew(certbot_test_no_force_renew):
    def func(args):
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        return certbot_test_no_force_renew(args)

    return func


@pytest.fixture(scope='module')
def common(common_no_force_renew):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        return common_no_force_renew(args)

    return func


@pytest.fixture(scope='module', autouse=True)
def http_server(http_01_port):
    def run():
        socketserver.TCPServer(('', http_01_port),
                               SimpleHTTPServer.SimpleHTTPRequestHandler).serve_forever()

    process = multiprocessing.Process(target=run)
    process.start()

    yield

    process.terminate()


@pytest.fixture()
def generate_test_hooks(renewal_hooks_dirs):
    renewal_hooks_execution_probe = tempfile.mkstemp()
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
'''.format(renewal_dir_deploy_hook, renewal_hooks_execution_probe)
            else:
                data = '''\
                
'''
            with open(hook_path, 'w') as file:
                file.write(data)
            os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IEXEC)

            yield {
                'renewal_hooks_execution_probe': renewal_hooks_execution_probe,
                'renewal_dir_pre_hook': renewal_dir_pre_hook,
                'renewal_dir_deploy_hook': renewal_dir_deploy_hook,
                'renewal_dir_post_hook': renewal_dir_post_hook
            }
    finally:
        os.unlink(renewal_hooks_execution_probe)
        for hook_dir in renewal_hooks_dirs:
            os.unlink(os.path.join(hook_dir, 'hook.{0}'.format(extension)))


@pytest.mark.incremental
class TestSuite(object):

    def test_directory_accessibility(self, acme_url):
        context = ssl.SSLContext()
        urlopen(acme_url, context=context)

    def test_basic_commands(self, common):
        initial_count_tmpfiles = len(os.listdir(tempfile.tempdir))

        with pytest.raises(subprocess.CalledProcessError):
            common(['--csr'])
        common(['--help'])
        common(['--help', 'all'])
        common(['--version'])

        new_count_tmpfiles = len(os.listdir(tempfile.tempdir))
        assert initial_count_tmpfiles == new_count_tmpfiles

    def test_hook_dirs_creation(self, common, renewal_hooks_dirs):
        common(['register'])

        for hook_dir in renewal_hooks_dirs:
            assert os.path.isdir(hook_dir)

    def test_registration_override(self, common):
        common(['unregister'])
        common(['register', '--email', 'ex1@domain.org,ex2@domain.org'])
        common(['register', '--update-registration', '--email', 'ex1@domain.org'])
        common(['register', '--update-registration', '--email', 'ex1@domain.org,ex2@domain.org'])

    def test_prepare_plugins(self, common):
        output = common(['plugins', '--init', 'prepare'])

        assert 'webroot' in output

