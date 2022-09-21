"""This module contains advanced assertions for the certbot integration tests."""
import io
import os
from typing import Optional
from typing import Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurve
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

try:
    import grp
    POSIX_MODE = True
except ImportError:
    import win32security
    import ntsecuritycon
    POSIX_MODE = False

EVERYBODY_SID = 'S-1-1-0'
SYSTEM_SID = 'S-1-5-18'
ADMINS_SID = 'S-1-5-32-544'


def assert_elliptic_key(key: str, curve: Type[EllipticCurve]) -> None:
    """
    Asserts that the key at the given path is an EC key using the given curve.
    :param key: path to key
    :param EllipticCurve curve: name of the expected elliptic curve
    """
    with open(key, 'rb') as file:
        privkey1 = file.read()

    key = load_pem_private_key(data=privkey1, password=None, backend=default_backend())

    assert isinstance(key, EllipticCurvePrivateKey)
    assert isinstance(key.curve, curve)


def assert_rsa_key(key: str, key_size: Optional[int] = None) -> None:
    """
    Asserts that the key at the given path is an RSA key.
    :param str key: path to key
    :param int key_size: if provided, assert that the RSA key is of this size
    """
    with open(key, 'rb') as file:
        privkey1 = file.read()

    key = load_pem_private_key(data=privkey1, password=None, backend=default_backend())
    assert isinstance(key, RSAPrivateKey)
    if key_size:
        assert key_size == key.key_size


def assert_hook_execution(probe_path: str, probe_content: str) -> None:
    """
    Assert that a certbot hook has been executed
    :param str probe_path: path to the file that received the hook output
    :param str probe_content: content expected when the hook is executed
    """
    encoding = 'utf-8' if POSIX_MODE else 'utf-16'
    with io.open(probe_path, 'rt', encoding=encoding) as file:
        data = file.read()

    lines = [line.strip() for line in data.splitlines()]
    assert probe_content in lines


def assert_saved_lineage_option(config_dir: str, lineage: str,
                                option: str, value: Optional[str] = None) -> None:
    """
    Assert that the option of a lineage has been saved.
    :param str config_dir: location of the certbot configuration
    :param str lineage: lineage domain name
    :param str option: the option key
    :param value: if desired, the expected option value
    """
    with open(os.path.join(config_dir, 'renewal', '{0}.conf'.format(lineage))) as file_h:
        assert f"{option} = {value if value else ''}" in file_h.read()


def assert_saved_renew_hook(config_dir: str, lineage: str) -> None:
    """
    Assert that the renew hook configuration of a lineage has been saved.
    :param str config_dir: location of the certbot configuration
    :param str lineage: lineage domain name
    """
    assert_saved_lineage_option(config_dir, lineage, 'renew_hook')


def assert_cert_count_for_lineage(config_dir: str, lineage: str, count: int) -> None:
    """
    Assert the number of certificates generated for a lineage.
    :param str config_dir: location of the certbot configuration
    :param str lineage: lineage domain name
    :param int count: number of expected certificates
    """
    archive_dir = os.path.join(config_dir, 'archive')
    lineage_dir = os.path.join(archive_dir, lineage)
    certs = [file for file in os.listdir(lineage_dir) if file.startswith('cert')]
    assert len(certs) == count


def assert_equals_group_permissions(file1: str, file2: str) -> None:
    """
    Assert that two files have the same permissions for group owner.
    :param str file1: first file path to compare
    :param str file2: second file path to compare
    """
    # On Windows there is no group, so this assertion does nothing on this platform
    if POSIX_MODE:
        mode_file1 = os.stat(file1).st_mode & 0o070
        mode_file2 = os.stat(file2).st_mode & 0o070

        assert mode_file1 == mode_file2


def assert_equals_world_read_permissions(file1: str, file2: str) -> None:
    """
    Assert that two files have the same read permissions for everyone.
    :param str file1: first file path to compare
    :param str file2: second file path to compare
    """
    if POSIX_MODE:
        mode_file1 = os.stat(file1).st_mode & 0o004
        mode_file2 = os.stat(file2).st_mode & 0o004
    else:
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID) # pylint: disable=used-before-assignment

        security1 = win32security.GetFileSecurity(file1, win32security.DACL_SECURITY_INFORMATION)
        dacl1 = security1.GetSecurityDescriptorDacl()

        mode_file1 = dacl1.GetEffectiveRightsFromAcl({
            'TrusteeForm': win32security.TRUSTEE_IS_SID,
            'TrusteeType': win32security.TRUSTEE_IS_USER,
            'Identifier': everybody,
        })
        mode_file1 = mode_file1 & ntsecuritycon.FILE_GENERIC_READ # pylint: disable=used-before-assignment

        security2 = win32security.GetFileSecurity(file2, win32security.DACL_SECURITY_INFORMATION)
        dacl2 = security2.GetSecurityDescriptorDacl()

        mode_file2 = dacl2.GetEffectiveRightsFromAcl({
            'TrusteeForm': win32security.TRUSTEE_IS_SID,
            'TrusteeType': win32security.TRUSTEE_IS_USER,
            'Identifier': everybody,
        })
        mode_file2 = mode_file2 & ntsecuritycon.FILE_GENERIC_READ

    assert mode_file1 == mode_file2


def assert_equals_group_owner(file1: str, file2: str) -> None:
    """
    Assert that two files have the same group owner.
    :param str file1: first file path to compare
    :param str file2: second file path to compare
    """
    # On Windows there is no group, so this assertion does nothing on this platform
    if POSIX_MODE:
        group_owner_file1 = grp.getgrgid(os.stat(file1).st_gid)[0]
        group_owner_file2 = grp.getgrgid(os.stat(file2).st_gid)[0]

        assert group_owner_file1 == group_owner_file2


def assert_world_no_permissions(file: str) -> None:
    """
    Assert that the given file is not world-readable.
    :param str file: path of the file to check
    """
    if POSIX_MODE:
        mode_file_all = os.stat(file).st_mode & 0o007
        assert mode_file_all == 0
    else:
        security = win32security.GetFileSecurity(file, win32security.DACL_SECURITY_INFORMATION)
        dacl = security.GetSecurityDescriptorDacl()
        mode = dacl.GetEffectiveRightsFromAcl({
            'TrusteeForm': win32security.TRUSTEE_IS_SID,
            'TrusteeType': win32security.TRUSTEE_IS_USER,
            'Identifier': win32security.ConvertStringSidToSid(EVERYBODY_SID),
        })

        assert not mode


def assert_world_read_permissions(file: str) -> None:
    """
    Assert that the given file is world-readable, but not world-writable or world-executable.
    :param str file: path of the file to check
    """
    if POSIX_MODE:
        mode_file_all = os.stat(file).st_mode & 0o007
        assert mode_file_all == 4
    else:
        security = win32security.GetFileSecurity(file, win32security.DACL_SECURITY_INFORMATION)
        dacl = security.GetSecurityDescriptorDacl()
        mode = dacl.GetEffectiveRightsFromAcl({
            'TrusteeForm': win32security.TRUSTEE_IS_SID,
            'TrusteeType': win32security.TRUSTEE_IS_USER,
            'Identifier': win32security.ConvertStringSidToSid(EVERYBODY_SID),
        })

        assert not mode & ntsecuritycon.FILE_GENERIC_WRITE
        assert not mode & ntsecuritycon.FILE_GENERIC_EXECUTE
        assert mode & ntsecuritycon.FILE_GENERIC_READ == ntsecuritycon.FILE_GENERIC_READ
