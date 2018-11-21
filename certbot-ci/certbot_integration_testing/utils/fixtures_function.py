import os
import multiprocessing
import tempfile
import sys
import stat

import pytest
from six.moves import socketserver
from six.moves import SimpleHTTPServer


@pytest.fixture
def http_01_server(http_01_port):
    def run():
        socketserver.TCPServer(('', http_01_port),
                               SimpleHTTPServer.SimpleHTTPRequestHandler).serve_forever()

    process = multiprocessing.Process(target=run)
    process.start()

    yield process.is_alive()

    process.terminate()


@pytest.fixture
def tls_sni_01_server(tls_sni_01_port):
    def run():
        socketserver.TCPServer(('', tls_sni_01_port),
                               SimpleHTTPServer.SimpleHTTPRequestHandler).serve_forever()

    process = multiprocessing.Process(target=run)
    process.start()

    yield process.is_alive()

    process.terminate()


@pytest.fixture
def hook_probe():
    probe = tempfile.mkstemp()
    try:
        yield probe[0]
    finally:
        os.unlink(probe)


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
