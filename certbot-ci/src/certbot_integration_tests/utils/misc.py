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
import json
import os
import re
import shutil
import socketserver
import stat
import sys
import tempfile
import threading
import time
from typing import Any
from typing import Generator
from typing import Iterable
from typing import Optional
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
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import load_pem_x509_certificate

import requests

from certbot_integration_tests.utils.constants import PEBBLE_ALTERNATE_ROOTS
from certbot_integration_tests.utils.constants import PEBBLE_MANAGEMENT_URL

RSA_KEY_TYPE = 'rsa'
ECDSA_KEY_TYPE = 'ecdsa'


def _suppress_x509_verification_warnings() -> None:
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
    _suppress_x509_verification_warnings()
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


def list_renewal_hooks_dirs(config_dir: str) -> list[str]:
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
def manual_http_hooks(http_server_root: str) -> Generator[tuple[str, str], None, None]:
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


def _format_extension_value(ext: x509.Extension[Any]) -> list[str]:
    """Format a single X.509 extension value."""
    lines = []

    # Format extension values
    if isinstance(ext.value, x509.SubjectAlternativeName):
        san_list = []
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                san_list.append(f"DNS:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                san_list.append(f"email:{name.value}")
            elif isinstance(name, x509.IPAddress):
                san_list.append(f"IP Address:{name.value}")
            elif isinstance(name, x509.UniformResourceIdentifier):
                san_list.append(f"URI:{name.value}")
            else:
                san_list.append(str(name))
        lines.append("                " + ", ".join(san_list))

    elif isinstance(ext.value, x509.KeyUsage):
        usages = []
        if ext.value.digital_signature:
            usages.append("Digital Signature")
        if ext.value.content_commitment:
            usages.append("Non Repudiation")
        if ext.value.key_encipherment:
            usages.append("Key Encipherment")
        if ext.value.data_encipherment:
            usages.append("Data Encipherment")
        if ext.value.key_agreement:
            usages.append("Key Agreement")
        if ext.value.key_cert_sign:
            usages.append("Certificate Sign")
        if ext.value.crl_sign:
            usages.append("CRL Sign")
        try:
            if ext.value.encipher_only:
                usages.append("Encipher Only")
        except ValueError:
            pass
        try:
            if ext.value.decipher_only:
                usages.append("Decipher Only")
        except ValueError:
            pass
        lines.append("                " + ", ".join(usages))

    elif isinstance(ext.value, x509.ExtendedKeyUsage):
        usage_map = {
            ExtendedKeyUsageOID.SERVER_AUTH: "TLS Web Server Authentication",
            ExtendedKeyUsageOID.CLIENT_AUTH: "TLS Web Client Authentication",
            ExtendedKeyUsageOID.CODE_SIGNING: "Code Signing",
            ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-mail Protection",
            ExtendedKeyUsageOID.TIME_STAMPING: "Time Stamping",
            ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP Signing"
        }
        usage_names = [usage_map.get(usage, str(usage)) for usage in ext.value]
        lines.append("                " + ", ".join(usage_names))

    elif isinstance(ext.value, x509.BasicConstraints):
        if ext.value.ca:
            if ext.value.path_length is not None:
                path_len = ext.value.path_length
                lines.append(f"                CA:TRUE, pathlen:{path_len}")
            else:
                lines.append("                CA:TRUE")
        else:
            lines.append("                CA:FALSE")

    elif isinstance(ext.value, x509.SubjectKeyIdentifier):
        ski_hex = ext.value.digest.hex().upper()
        ski_formatted = ":".join([ski_hex[i:i + 2] for i in range(0, len(ski_hex), 2)])
        lines.append(f"                {ski_formatted}")

    elif isinstance(ext.value, x509.AuthorityKeyIdentifier):
        if ext.value.key_identifier:
            aki_hex = ext.value.key_identifier.hex().upper()
            aki_formatted = ":".join(
                [aki_hex[i:i + 2] for i in range(0, len(aki_hex), 2)])
            lines.append(f"                keyid:{aki_formatted}")
    else:
        # For other extensions, show basic representation
        lines.append(f"                {str(ext.value)}")

    return lines


def _format_certificate_text(cert: x509.Certificate) -> str:
    """
    Format an X509 certificate as human readable text using cryptography library.
    This implementation matches OpenSSL's X509_print_ex behavior exactly.
    :param cert: the certificate to format
    :returns: the TEXT version of the certificate, similar to openssl x509 -text output
    """
    lines = []

    # Certificate header
    lines.append("Certificate:")
    lines.append("    Data:")

    # Version
    version_num = cert.version.value
    lines.append(f"        Version: {version_num + 1} (0x{version_num:x})")

    # Serial Number - format exactly like OpenSSL (single line)
    serial_hex = f"{cert.serial_number:x}"
    if len(serial_hex) % 2:
        serial_hex = "0" + serial_hex

    # Format as single line with colon separators
    hex_pairs = [serial_hex[i:i + 2] for i in range(0, len(serial_hex), 2)]
    serial_formatted = ":".join(hex_pairs)

    lines.append("        Serial Number:")
    lines.append(f"            {serial_formatted}")

    # Signature Algorithm
    lines.append(f"        Signature Algorithm: "
                 f"{cert.signature_algorithm_oid._name}")  # pylint: disable=protected-access

    name_map = {
        x509.NameOID.COUNTRY_NAME: "C",
        x509.NameOID.STATE_OR_PROVINCE_NAME: "ST",
        x509.NameOID.LOCALITY_NAME: "L",
        x509.NameOID.ORGANIZATION_NAME: "O",
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        x509.NameOID.COMMON_NAME: "CN",
        x509.NameOID.EMAIL_ADDRESS: "emailAddress"
    }
    # Issuer - format without spaces around =
    issuer_parts = []
    for attribute in cert.issuer:
        name = name_map.get(attribute.oid, attribute.oid._name) # pylint: disable=protected-access
        issuer_parts.append(f"{name}={attribute.value}")
    lines.append(f"        Issuer: {', '.join(issuer_parts)}")

    # Validity
    lines.append("        Validity")
    not_before = cert.not_valid_before_utc.strftime('%b %d %H:%M:%S %Y GMT')
    lines.append(f"            Not Before: {not_before}")
    not_after = cert.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y GMT')
    lines.append(f"            Not After : {not_after}")

    # Subject - format without spaces around =
    subject_parts = []
    for attribute in cert.subject:
        name = name_map.get(attribute.oid, attribute.oid._name) # pylint: disable=protected-access
        subject_parts.append(f"{name}={attribute.value}")
    lines.append(f"        Subject: {', '.join(subject_parts)}")

    # Public Key Info
    lines.append("        Subject Public Key Info:")
    public_key = cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        lines.append("            Public Key Algorithm: rsaEncryption")
        # Use OpenSSL format: "Public-Key:" not "RSA Public-Key:"
        lines.append(f"                Public-Key: ({public_key.key_size} bit)")
        lines.append("                Modulus:")

        # Format modulus exactly like OpenSSL
        modulus_hex = f"{public_key.public_numbers().n:x}"
        if len(modulus_hex) % 2:
            modulus_hex = "0" + modulus_hex

        # Add leading 00 and format as pairs
        modulus_with_leading_zero = "00" + modulus_hex
        hex_pairs = [modulus_with_leading_zero[i:i + 2]
                     for i in range(0, len(modulus_with_leading_zero), 2)]

        # Format lines: 15 bytes per line
        for line_start in range(0, len(hex_pairs), 15):
            line_pairs = hex_pairs[line_start:line_start + 15]
            line_text = ":".join(line_pairs)

            # Add trailing colon except for the last line
            if line_start + 15 < len(hex_pairs):
                line_text += ":"

            lines.append(f"                    {line_text}")

        # Exponent
        exponent = public_key.public_numbers().e
        lines.append(f"                Exponent: {exponent} (0x{exponent:x})")

    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        lines.append("            Public Key Algorithm: id-ecPublicKey")
        lines.append(f"                Public-Key: ({public_key.curve.key_size} bit)")
        lines.append("                pub:")
        # Format EC public key
        public_numbers = public_key.public_numbers()
        point_size = (public_key.curve.key_size + 7) // 8

        # Uncompressed point format: 0x04 + X + Y
        x_bytes = public_numbers.x.to_bytes(point_size, 'big')
        y_bytes = public_numbers.y.to_bytes(point_size, 'big')
        point_bytes = b'\x04' + x_bytes + y_bytes

        pub_hex = point_bytes.hex()
        hex_pairs = [pub_hex[i:i + 2] for i in range(0, len(pub_hex), 2)]
        for line_start in range(0, len(hex_pairs), 15):
            line_pairs = hex_pairs[line_start:line_start + 15]
            line_text = ":".join(line_pairs)
            if line_start + 15 < len(hex_pairs):
                line_text += ":"
            lines.append(f"                    {line_text}")
        lines.append(f"                ASN1 OID: {public_key.curve.name}")
        lines.append(f"                NIST CURVE: {public_key.curve.name}")

    # Extensions
    try:
        extensions = cert.extensions
        if extensions:
            lines.append("        X509v3 extensions:")
            ext_name_map = {
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "X509v3 Subject Alternative Name",
                ExtensionOID.KEY_USAGE: "X509v3 Key Usage",
                ExtensionOID.EXTENDED_KEY_USAGE: "X509v3 Extended Key Usage",
                ExtensionOID.BASIC_CONSTRAINTS: "X509v3 Basic Constraints",
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "X509v3 Authority Key Identifier",
                ExtensionOID.SUBJECT_KEY_IDENTIFIER: "X509v3 Subject Key Identifier",
                ExtensionOID.CERTIFICATE_POLICIES: "X509v3 Certificate Policies",
                ExtensionOID.CRL_DISTRIBUTION_POINTS: "X509v3 CRL Distribution Points",
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "Authority Information Access"
            }
            for ext in extensions:
                ext_name = ext_name_map.get(ext.oid, ext.oid._name) # pylint: disable=protected-access
                critical_text = " critical" if ext.critical else " "
                lines.append(f"            {ext_name}:{critical_text}")
                lines.extend(_format_extension_value(ext))
    except (ValueError, AttributeError, TypeError):
        # Skip extensions that can't be processed
        pass

    # Signature Algorithm and Value (no extra padding line)
    lines.append(f"    Signature Algorithm: "
                 f"{cert.signature_algorithm_oid._name}")  # pylint: disable=protected-access
    lines.append("    Signature Value:")

    # Format signature: 18 bytes per line
    signature_hex = cert.signature.hex()
    hex_pairs = [signature_hex[i:i + 2] for i in range(0, len(signature_hex), 2)]

    for line_start in range(0, len(hex_pairs), 18):
        line_pairs = hex_pairs[line_start:line_start + 18]
        line_text = ":".join(line_pairs)

        # Add trailing colon except for the last line
        if line_start + 18 < len(hex_pairs):
            line_text += ":"

        lines.append(f"        {line_text}")

    # Add final empty line to match OpenSSL
    lines.append("")

    return "\n".join(lines)


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
    return _format_certificate_text(cert)


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


def get_acme_issuers() -> list[Certificate]:
    """Gets the list of one or more issuer certificates from the ACME server used by the
    context.
    :param context: the testing context.
    :return: the `list of x509.Certificate` representing the list of issuers.
    """
    _suppress_x509_verification_warnings()

    issuers = []
    for i in range(PEBBLE_ALTERNATE_ROOTS + 1):
        request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediates/{}'.format(i),
                               verify=False,
                               timeout=10)
        issuers.append(load_pem_x509_certificate(request.content, default_backend()))

    return issuers

def set_ari_response(certificate_pem: str, response_json: str) -> None:
    """POST to an endpoint on the Pebble server setting the ARI response
    for the given certificate."""
    set_renewal_info_body = json.dumps(
        {
            'certificate': certificate_pem,
            'ariResponse': response_json,
        })

    _suppress_x509_verification_warnings()
    url = PEBBLE_MANAGEMENT_URL + '/set-renewal-info/'
    print(f'sending to {url}: {set_renewal_info_body}')
    resp = requests.post(url, verify=False, timeout=10, data=set_renewal_info_body)
    if resp.status_code != 200:
        print(f'setting renewal info: {resp.status_code} {resp.text}')
    assert resp.status_code == 200
