import subprocess
import os
import ssl
import time
import contextlib
import tempfile
import shutil
import multiprocessing
import sys
import stat
import errno

from six.moves.urllib.request import urlopen
from six.moves import socketserver, SimpleHTTPServer
from OpenSSL import crypto


class GraceFullTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def find_certbot_root_directory():
    script_path = os.path.realpath(__file__)
    current_dir = os.path.dirname(script_path)

    while '.git' not in os.listdir(current_dir) and current_dir != os.path.dirname(current_dir):
        current_dir = os.path.dirname(current_dir)

    dirs = os.listdir(current_dir)
    if '.git' not in dirs:
        raise ValueError('Error, could not find certbot sources root directory')

    return current_dir


def generate_csr(domains, key_path, csr_path, key_type='RSA'):
    certbot_root_directory = find_certbot_root_directory()
    script_path = os.path.normpath(os.path.join(certbot_root_directory, 'examples/generate-csr.py'))

    command = [
        sys.executable, script_path, '--key-path', key_path, '--csr-path', csr_path,
        '--key-type', key_type
    ]
    command.extend(domains)
    subprocess.check_call(command)


def check_until_timeout(url):
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)

    for _ in range(0, 150):
        time.sleep(1)
        try:
            if urlopen(url, context=context).getcode() == 200:
                return
        except IOError:
            pass

    raise ValueError('Error, url did not respond after 150 attempts: {0}'.format(url))


def read_certificate(cert_path):
    with open(cert_path, 'r') as file:
        data = file.read()

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, data.encode('utf-8'))
    return crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode('utf-8')


@contextlib.contextmanager
def create_tcp_server(port):
    current_cwd = os.getcwd()
    webroot = tempfile.mkdtemp()

    def run():
        GraceFullTCPServer(('', port), SimpleHTTPServer.SimpleHTTPRequestHandler).serve_forever()

    process = multiprocessing.Process(target=run)

    try:
        try:
            os.chdir(webroot)
            process.start()
        finally:
            os.chdir(current_cwd)

        check_until_timeout('http://localhost:{0}/'.format(port))

        yield webroot
    finally:
        try:
            if process.is_alive():
                process.terminate()
                process.join()  # Block until process is effectively terminated
        finally:
            shutil.rmtree(webroot)


def list_renewal_hooks_dirs(config_dir):
    renewal_hooks_root = os.path.join(config_dir, 'renewal-hooks')
    return [os.path.join(renewal_hooks_root, item) for item in ['pre', 'deploy', 'post']]


def generate_test_file_hooks(config_dir, hook_probe):
    if sys.platform == 'win32':
        extension = 'bat'
    else:
        extension = 'sh'

    renewal_hooks_dirs = list_renewal_hooks_dirs(config_dir)

    for hook_dir in renewal_hooks_dirs:
        try:
            os.makedirs(hook_dir)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
        hook_path = os.path.join(hook_dir, 'hook.{0}'.format(extension))
        if extension == 'sh':
            data = '''\
#!/bin/bash -xe
if [ "$0" == "{0}" ]; then
    if [ -z "$RENEWED_DOMAINS" -o -z "$RENEWED_LINEAGE" ]; then
        echo "Environment variables not properly set!" >&2
        exit 1
    fi
fi
echo $(basename $(dirname "$0")) >> "{1}"\
'''.format(hook_path, hook_probe)
        else:
            data = '''\

'''
        with open(hook_path, 'w') as file:
            file.write(data)
        os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IEXEC)


def node_is_master(config):
    """
    Check if current config node represents the master node in pytest-xdist execution.
    :param config: Node configuration object
    :return: True if current node is master (or xdist is not used), False otherwise
    """
    return hasattr(config, 'slaveinput')


@contextlib.contextmanager
def execute_in_given_cwd(cwd):
    current_cwd = os.getcwd()
    try:
        os.chdir(cwd)
        yield
    finally:
        os.chdir(current_cwd)
