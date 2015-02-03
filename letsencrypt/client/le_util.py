"""Utilities for all Let"s Encrypt."""
import base64
import collections
import errno
import os
import stat

from letsencrypt.client import errors


Key = collections.namedtuple("Key", "file pem")
# Note: form is the type of data, "pem" or "der"
CSR = collections.namedtuple("CSR", "file data form")


def make_or_verify_dir(directory, mode=0o755, uid=0):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.

    :raises LetsEncryptClientError: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if not check_permissions(directory, mode, uid):
                raise errors.LetsEncryptClientError(
                    "%s exists, but does not have the proper "
                    "permissions or owner" % directory)
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param str filepath: Path to the tested file (or directory).
    :param int mode: Expected file mode.
    :param int uid: Expected file owner.

    :returns: True if `mode` and `uid` match, False otherwise.
    :rtype: bool

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def unique_file(path, mode=0o777):
    """Safely finds a unique file for writing only (by default).

    :param str path: path/filename.ext
    :param int mode: File mode

    :return: tuple of file object and file name

    """
    path, tail = os.path.split(path)
    count = 0
    while True:
        fname = os.path.join(path, "%04d_%s" % (count, tail))
        try:
            file_d = os.open(fname, os.O_CREAT | os.O_EXCL | os.O_RDWR, mode)
            return os.fdopen(file_d, "w"), fname
        except OSError:
            pass
        count += 1


# https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#appendix-C
#
# Jose Base64:
#
#   - URL-safe Base64
#
#   - padding stripped


def jose_b64encode(data):
    """JOSE Base64 encode.

    :param data: Data to be encoded.
    :type data: str or bytearray

    :returns: JOSE Base64 string.
    :rtype: str

    :raises TypeError: if `data` is of incorrect type

    """
    if not isinstance(data, str):
        raise TypeError("argument should be str or bytearray")
    return base64.urlsafe_b64encode(data).rstrip("=")


def jose_b64decode(data):
    """JOSE Base64 decode.

    :param data: Base64 string to be decoded. If it's unicode, then
                 only ASCII characters are allowed.
    :type data: str or unicode

    :returns: Decoded data.

    :raises TypeError: if input is of incorrect type
    :raises ValueError: if input is unicode with non-ASCII characters

    """
    if isinstance(data, unicode):
        try:
            data = data.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError(
                "unicode argument should contain only ASCII characters")
    elif not isinstance(data, str):
        raise TypeError("argument should be a str or unicode")

    return base64.urlsafe_b64decode(data + "=" * (4 - (len(data) % 4)))
