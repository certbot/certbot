import subprocess
import os
import re
import unittest
import ssl
import time
import contextlib
import tempfile
import shutil
import multiprocessing
import sys
from pprint import pprint

from six.moves.urllib.request import urlopen
from six.moves import socketserver, SimpleHTTPServer
from OpenSSL import crypto


class GraceFullTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def find_certbot_executable():
    try:
        return subprocess.check_output('which certbot',
                                       shell=True, universal_newlines=True).strip()
    except subprocess.CalledProcessError:
        try:
            return subprocess.check_output('where certbot',
                                           shell=True, universal_newlines=True).strip()
        except subprocess.CalledProcessError:
            pass

    raise ValueError('Error, could not find certbot executable')


def find_certbot_root_directory():
    script_path = os.path.realpath(__file__)
    current_dir = os.path.dirname(script_path)

    while '.git' not in os.listdir(current_dir) and current_dir != os.path.dirname(current_dir):
        current_dir = os.path.dirname(current_dir)

    dirs = os.listdir(current_dir)
    if '.git' not in dirs:
        raise ValueError('Error, could not find certbot sources root directory')

    return current_dir


def find_certbot_sources():
    certbot_root_directory = find_certbot_root_directory()

    return [os.path.join(certbot_root_directory, dir) for dir in os.listdir(certbot_root_directory)
            if (dir == 'acme' or (re.match('^certbot.*$', dir)
                                  and dir not in ['certbot-ci', 'certbot.egg-info']))
            and os.path.isdir(dir)]


def generate_csr(domains, key_path, csr_path):
    certbot_root_directory = find_certbot_root_directory()
    script_path = os.path.normpath(os.path.join(certbot_root_directory, 'examples/generate-csr.py'))

    subprocess.check_call([
        sys.executable, script_path, '--key-path', key_path, '--csr-path', csr_path, *domains])


def skip_on_pebble(reason):
    """
    Decorator to skip a test against Pebble instances.
    A reason is required.
    """
    def wrapper(func):
        """Wrapped version"""
        return unittest.skipIf('pebble' in os.environ.get('CERTBOT_INTEGRATION'), reason)(func)
    return wrapper


def skip_on_pebble_strict(reason):
    """
    Decorator to skip a test against Pebble instances with strict mode enabled.
    A reason is required.
    """
    def wrapper(func):
        """Wrapped version"""
        return unittest.skipIf(os.environ.get('CERTBOT_INTEGRATION')
                               == 'pebble-strict', reason)(func)
    return wrapper


def check_until_timeout(url):
    context = ssl.SSLContext()

    for _ in range(0, 150):
        time.sleep(1)
        try:
            if urlopen(url, context=context).getcode() == 200:
                return
        except IOError:
            pass

    raise ValueError('Error, url did not respond after 150 attempts: {0}'.format(url))


def print_certificate(cert_path):
    with open(cert_path, 'r') as file:
        data = file.read()

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, data.encode('utf-8'))
    print(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode('utf-8'))


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
