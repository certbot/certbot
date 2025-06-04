"""
Misc module contains stateless functions that could be used during pytest execution,
or outside during setup/teardown of the integration tests environment.
"""
import atexit
import contextlib
import errno
import functools
import http.server as SimpleHTTPServer
import importlib.resources
import os
import re
import shutil
import socketserver
import stat
import sys
import tempfile
import threading
import time
from typing import Generator
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.x509 import Certificate
from cryptography.x509 import load_pem_x509_certificate
from OpenSSL import crypto
import requests

from certbot_integration_tests.utils.constants import PEBBLE_ALTERNATE_ROOTS
from certbot_integration_tests.utils.constants import PEBBLE_MANAGEMENT_URL

RSA_KEY_TYPE = 'rsa'
ECDSA_KEY_TYPE = 'ecdsa'


def suppress_x509_verification_warnings() -> None:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_until_timeout(url: str, attempts: int = 30) -> None:
    """
    Wait and block until given url responds with status 200, or raise an exception
    after the specified number of attempts.
    :param str url: the URL to test
    :param int attempts: the number of times to try to connect to the URL
    :raise ValueError: exception raised if unable to reach the URL
    """
    suppress_x509_verification_warnings()
    for _ in range(attempts):
        time.sleep(1)
        try:
            if requests.get(url, verify=False, timeout=10).status_code == 200:
                return
        except requests.exceptions.RequestException:
            pass

    raise ValueError('Error, url did not respond after {0} attempts: {1}'.format(attempts, url))


class GracefulTCPServer(socketserver.TCPServer):
    """
    This subclass of TCPServer allows graceful reuse of an address that has
    just been released by another instance of TCPServer.
    """
    allow_reuse_address = True


@contextlib.contextmanager
def create_http_server(port: int) -> Generator[str, None, None]:
    """
    Setup and start an HTTP server for the given TCP port.
    This server stays active for the lifetime of the context, and is automatically
    stopped with context exit, while its temporary webroot is deleted.
    :param int port: the TCP port to use
    :return str: the temporary webroot attached to this server
    """
    with tempfile.TemporaryDirectory() as webroot:
        # Setting the directory argument of SimpleHTTPRequestHandler causes
        # files to be served from that directory.
        handler = functools.partial(SimpleHTTPServer.SimpleHTTPRequestHandler, directory=webroot)
        server = GracefulTCPServer(('', port), handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            check_until_timeout('http://localhost:{0}/'.format(port))
            yield webroot
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


def list_renewal_hooks_dirs(config_dir: str) -> List[str]:
    """
    Find and return paths of all hook directories for the given certbot config directory
    :param str config_dir: path to the certbot config directory
    :return str[]: list of path to the standard hooks directory for this certbot instance
    """
    renewal_hooks_root = os.path.join(config_dir, 'renewal-hooks')
    return [os.path.join(renewal_hooks_root, item) for item in ['pre', 'deploy', 'post']]


def generate_test_file_hooks(config_dir: str, hook_probe: str) -> None:
    """
    Create a suite of certbot hook scripts and put them in the relevant hook directory
    for the given certbot configuration directory. These scripts, when executed, will write
    specific verbs in the given hook_probe file to allow asserting they have effectively
    been executed. The deploy hook also checks that the renewal environment variables are set.
    :param str config_dir: current certbot config directory
    :param str hook_probe: path to the hook probe to test hook scripts execution
    """
    file_manager = contextlib.ExitStack()
    atexit.register(file_manager.close)
    hook_path_ref = (importlib.resources.files('certbot_integration_tests').joinpath('assets')
                     .joinpath('hook.py'))
    hook_path = str(file_manager.enter_context(importlib.resources.as_file(hook_path_ref)))

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
"{0}" "{1}" "{2}" >> "{3}"
'''.format(sys.executable, hook_path, entrypoint_script_path, hook_probe)
        else:
            entrypoint_script_path = os.path.join(hook_dir, 'entrypoint.ps1')
            entrypoint_script = '''\
& "{0}" "{1}" "{2}" >> "{3}"
            '''.format(sys.executable, hook_path, entrypoint_script_path, hook_probe)

        with open(entrypoint_script_path, 'w') as file_h:
            file_h.write(entrypoint_script)

        os.chmod(entrypoint_script_path, os.stat(entrypoint_script_path).st_mode | stat.S_IEXEC)


@contextlib.contextmanager
def manual_http_hooks(http_server_root: str) -> Generator[Tuple[str, str], None, None]:
    """
    Generate suitable http-01 hooks command for test purpose in the given HTTP
    server webroot directory. These hooks command use temporary python scripts
    that are deleted upon context exit.
    :param str http_server_root: path to the HTTP server configured to serve http-01 challenges
    :return (str, str): a tuple containing the authentication hook and cleanup hook commands
    """
    tempdir = tempfile.mkdtemp()
    try:
        auth_script_path = os.path.join(tempdir, 'auth.py')
        with open(auth_script_path, 'w') as file_h:
            file_h.write('''\
#!/usr/bin/env python
import os
challenge_dir = os.path.join('{0}', '.well-known', 'acme-challenge')
os.makedirs(challenge_dir)
challenge_file = os.path.join(challenge_dir, os.environ.get('CERTBOT_TOKEN'))
with open(challenge_file, 'w') as file_h:
    file_h.write(os.environ.get('CERTBOT_VALIDATION'))
'''.format(http_server_root.replace('\\', '\\\\')))
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


def generate_csr(
    domains: Iterable[str], key_path: str, csr_path: str, key_type: str = RSA_KEY_TYPE
) -> None:
    """
    Generate a private key, and a CSR for the given domains using this key.
    :param domains: the domain names to include in the CSR
    :type domains: `list` of `str`
    :param str key_path: path to the private key that will be generated
    :param str csr_path: path to the CSR that will be generated
    :param str key_type: type of the key (misc.RSA_KEY_TYPE or misc.ECDSA_KEY_TYPE)
    """
    key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    if key_type == RSA_KEY_TYPE:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_type == ECDSA_KEY_TYPE:
        key = ec.generate_private_key(ec.SECP384R1())
    else:
        raise ValueError("Invalid key type: {0}".format(key_type))

    with open(key_path, "wb") as file_h:
        file_h.write(
            key.private_bytes(
                Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
            )
        )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(csr_path, "wb") as file_h:
        file_h.write(csr.public_bytes(Encoding.DER))


def read_certificate(cert_path: str) -> str:
    """
    Load the certificate from the provided path, and return a human readable version
    of it (TEXT mode).
    :param str cert_path: the path to the certificate
    :returns: the TEXT version of the certificate, as it would be displayed by openssl binary
    """
    with open(cert_path, "rb") as file:
        data = file.read()

    cert = x509.load_pem_x509_certificate(data)
    return crypto.dump_certificate(
        crypto.FILETYPE_TEXT, crypto.X509.from_cryptography(cert)
    ).decode("utf-8")


def load_sample_data_path(workspace: str) -> str:
    """
    Load the certbot configuration example designed to make OCSP tests, and return its path
    :param str workspace: current test workspace directory path
    :returns: the path to the loaded sample data directory
    :rtype: str
    """
    original_ref = (importlib.resources.files('certbot_integration_tests').joinpath('assets')
                    .joinpath('sample-config'))
    with importlib.resources.as_file(original_ref) as original:
        copied = os.path.join(workspace, 'sample-config')
        shutil.copytree(original, copied, symlinks=True)

    if os.name == 'nt':
        # Fix the symlinks on Windows if GIT is not configured to create them upon checkout
        for lineage in [
            'a.encryption-example.com',
            'b.encryption-example.com',
            'c.encryption-example.com',
        ]:
            current_live = os.path.join(copied, 'live', lineage)
            for name in os.listdir(current_live):
                if name != 'README':
                    current_file = os.path.join(current_live, name)
                    if not os.path.islink(current_file):
                        with open(current_file) as file_h:
                            src = file_h.read()
                        os.unlink(current_file)
                        os.symlink(os.path.join(current_live, src), current_file)

    return copied


def echo(keyword: str, path: Optional[str] = None) -> str:
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
    return '{0} -c "print(\'{1}\')"{2}'.format(
        os.path.basename(sys.executable), keyword, ' >> "{0}"'.format(path) if path else '')


def get_acme_issuers() -> List[Certificate]:
    """Gets the list of one or more issuer certificates from the ACME server used by the
    context.
    :param context: the testing context.
    :return: the `list of x509.Certificate` representing the list of issuers.
    """
    suppress_x509_verification_warnings()

    issuers = []
    for i in range(PEBBLE_ALTERNATE_ROOTS + 1):
        request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediates/{}'.format(i),
                               verify=False,
                               timeout=10)
        issuers.append(load_pem_x509_certificate(request.content, default_backend()))

    return issuers
