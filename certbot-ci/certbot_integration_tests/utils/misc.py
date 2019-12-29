"""
Misc module contains stateless functions that could be used during pytest execution,
or outside during setup/teardown of the integration tests environment.
"""
import contextlib
import errno
import multiprocessing
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import warnings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from OpenSSL import crypto
import pkg_resources
import requests
from six.moves import SimpleHTTPServer
from six.moves import socketserver

RSA_KEY_TYPE = 'rsa'
ECDSA_KEY_TYPE = 'ecdsa'


def check_until_timeout(url, attempts=30):
    """
    Wait and block until given url responds with status 200, or raise an exception
    after the specified number of attempts.
    :param str url: the URL to test
    :param int attempts: the number of times to try to connect to the URL
    :raise ValueError: exception raised if unable to reach the URL
    """
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        # Handle old versions of request with vendorized urllib3
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    for _ in range(attempts):
        time.sleep(1)
        try:
            if requests.get(url, verify=False).status_code == 200:
                return
        except requests.exceptions.ConnectionError:
            pass

    raise ValueError('Error, url did not respond after {0} attempts: {1}'.format(attempts, url))


class GracefulTCPServer(socketserver.TCPServer):
    """
    This subclass of TCPServer allows graceful reuse of an address that has
    just been released by another instance of TCPServer.
    """
    allow_reuse_address = True


def _run_server(port):
    GracefulTCPServer(('', port), SimpleHTTPServer.SimpleHTTPRequestHandler).serve_forever()


@contextlib.contextmanager
def create_http_server(port):
    """
    Setup and start an HTTP server for the given TCP port.
    This server stays active for the lifetime of the context, and is automatically
    stopped with context exit, while its temporary webroot is deleted.
    :param int port: the TCP port to use
    :return str: the temporary webroot attached to this server
    """
    current_cwd = os.getcwd()
    webroot = tempfile.mkdtemp()

    process = multiprocessing.Process(target=_run_server, args=(port,))

    try:
        # SimpleHTTPServer is designed to serve files from the current working directory at the
        # time it starts. So we temporarily change the cwd to our crafted webroot before launch.
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
    """
    Find and return paths of all hook directories for the given certbot config directory
    :param str config_dir: path to the certbot config directory
    :return str[]: list of path to the standard hooks directory for this certbot instance
    """
    renewal_hooks_root = os.path.join(config_dir, 'renewal-hooks')
    return [os.path.join(renewal_hooks_root, item) for item in ['pre', 'deploy', 'post']]


def generate_test_file_hooks(config_dir, hook_probe):
    """
    Create a suite of certbot hook scripts and put them in the relevant hook directory
    for the given certbot configuration directory. These scripts, when executed, will write
    specific verbs in the given hook_probe file to allow asserting they have effectively
    been executed. The deploy hook also checks that the renewal environment variables are set.
    :param str config_dir: current certbot config directory
    :param hook_probe: path to the hook probe to test hook scripts execution
    """
    hook_path = pkg_resources.resource_filename('certbot_integration_tests', 'assets/hook.py')

    for hook_dir in list_renewal_hooks_dirs(config_dir):
        # We want an equivalent of bash `chmod -p $HOOK_DIR, that does not fail if one folder of
        # the hierarchy already exists. It is not the case of os.makedirs. Python 3 has an
        # optional parameter `exists_ok` to not fail on existing dir, but Python 2.7 does not.
        # So we pass through a try except pass for it. To be removed with dropped support on py27.
        try:
            os.makedirs(hook_dir)
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise

        if os.name != 'nt':
            entrypoint_script_path = os.path.join(hook_dir, 'entrypoint.sh')
            entrypoint_script = '''\
#!/usr/bin/env bash
set -e
"{0}" "{1}" "{2}" "{3}"
'''.format(sys.executable, hook_path, entrypoint_script_path, hook_probe)
        else:
            entrypoint_script_path = os.path.join(hook_dir, 'entrypoint.bat')
            entrypoint_script = '''\
@echo off
"{0}" "{1}" "{2}" "{3}"
            '''.format(sys.executable, hook_path, entrypoint_script_path, hook_probe)

        with open(entrypoint_script_path, 'w') as file_h:
            file_h.write(entrypoint_script)

        os.chmod(entrypoint_script_path, os.stat(entrypoint_script_path).st_mode | stat.S_IEXEC)


@contextlib.contextmanager
def manual_http_hooks(http_server_root, http_port):
    """
    Generate suitable http-01 hooks command for test purpose in the given HTTP
    server webroot directory. These hooks command use temporary python scripts
    that are deleted upon context exit.
    :param str http_server_root: path to the HTTP server configured to serve http-01 challenges
    :param int http_port: HTTP port that the HTTP server listen on
    :return (str, str): a tuple containing the authentication hook and cleanup hook commands
    """
    tempdir = tempfile.mkdtemp()
    try:
        auth_script_path = os.path.join(tempdir, 'auth.py')
        with open(auth_script_path, 'w') as file_h:
            file_h.write('''\
#!/usr/bin/env python
import os
import requests
import time
import sys
challenge_dir = os.path.join('{0}', '.well-known', 'acme-challenge')
os.makedirs(challenge_dir)
challenge_file = os.path.join(challenge_dir, os.environ.get('CERTBOT_TOKEN'))
with open(challenge_file, 'w') as file_h:
    file_h.write(os.environ.get('CERTBOT_VALIDATION'))
url = 'http://localhost:{1}/.well-known/acme-challenge/' + os.environ.get('CERTBOT_TOKEN')
for _ in range(0, 10):
    time.sleep(1)
    try:
        if request.get(url).status_code == 200:
            sys.exit(0)
    except requests.exceptions.ConnectionError:
        pass
raise ValueError('Error, url did not respond after 10 attempts: {{0}}'.format(url))
'''.format(http_server_root.replace('\\', '\\\\'), http_port))
        os.chmod(auth_script_path, 0o755)

        cleanup_script_path = os.path.join(tempdir, 'cleanup.py')
        with open(cleanup_script_path, 'w') as file_h:
            file_h.write('''\
#!/usr/bin/env python
import os
import shutil
well_known = os.path.join('{0}', '.well-known')
shutil.rmtree(well_known)
'''.format(http_server_root.replace('\\', '\\\\')))
        os.chmod(cleanup_script_path, 0o755)

        yield ('{0} {1}'.format(sys.executable, auth_script_path),
               '{0} {1}'.format(sys.executable, cleanup_script_path))
    finally:
        shutil.rmtree(tempdir)


def generate_csr(domains, key_path, csr_path, key_type=RSA_KEY_TYPE):
    """
    Generate a private key, and a CSR for the given domains using this key.
    :param domains: the domain names to include in the CSR
    :type domains: `list` of `str`
    :param str key_path: path to the private key that will be generated
    :param str csr_path: path to the CSR that will be generated
    :param str key_type: type of the key (misc.RSA_KEY_TYPE or misc.ECDSA_KEY_TYPE)
    """
    if key_type == RSA_KEY_TYPE:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
    elif key_type == ECDSA_KEY_TYPE:
        with warnings.catch_warnings():
            # Ignore a warning on some old versions of cryptography
            warnings.simplefilter('ignore', category=PendingDeprecationWarning)
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=NoEncryption())
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
    else:
        raise ValueError('Invalid key type: {0}'.format(key_type))

    with open(key_path, 'wb') as file_h:
        file_h.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    req = crypto.X509Req()
    san = ', '.join(['DNS:{0}'.format(item) for item in domains])
    san_constraint = crypto.X509Extension(b'subjectAltName', False, san.encode('utf-8'))
    req.add_extensions([san_constraint])

    req.set_pubkey(key)
    req.set_version(2)
    req.sign(key, 'sha256')

    with open(csr_path, 'wb') as file_h:
        file_h.write(crypto.dump_certificate_request(crypto.FILETYPE_ASN1, req))


def read_certificate(cert_path):
    """
    Load the certificate from the provided path, and return a human readable version of it (TEXT mode).
    :param str cert_path: the path to the certificate
    :returns: the TEXT version of the certificate, as it would be displayed by openssl binary
    """
    with open(cert_path, 'rb') as file:
        data = file.read()

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
    return crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode('utf-8')


def load_sample_data_path(workspace):
    """
    Load the certbot configuration example designed to make OCSP tests, and return its path
    :param str workspace: current test workspace directory path
    :returns: the path to the loaded sample data directory
    :rtype: str
    """
    original = pkg_resources.resource_filename('certbot_integration_tests', 'assets/sample-config')
    copied = os.path.join(workspace, 'sample-config')
    shutil.copytree(original, copied, symlinks=True)

    if os.name == 'nt':
        # Fix the symlinks on Windows since GIT is not creating them upon checkout
        for lineage in ['a.encryption-example.com', 'b.encryption-example.com']:
            current_live = os.path.join(copied, 'live', lineage)
            for name in os.listdir(current_live):
                if name != 'README':
                    current_file = os.path.join(current_live, name)
                    with open(current_file) as file_h:
                        src = file_h.read()
                    os.unlink(current_file)
                    os.symlink(os.path.join(current_live, src), current_file)

    return copied


def echo(keyword, path=None):
    """
    Generate a platform independent executable command
    that echoes the given keyword into the given file.
    :param keyword: the keyword to echo (must be a single keyword)
    :param path: path to the file were keyword is echoed
    :return: the executable command
    """
    if not re.match(r'^\w+$', keyword):
        raise ValueError('Error, keyword `{0}` is not a single keyword.'
                         .format(keyword))
    return '{0} -c "from __future__ import print_function; print(\'{1}\')"{2}'.format(
        os.path.basename(sys.executable), keyword, ' >> "{0}"'.format(path) if path else '')
