"""Utilities for all Let's Encrypt."""
import base64
import errno
import os
import stat

from letsencrypt.client import errors


def make_or_verify_dir(directory, mode=0o755, uid=0):
    """Make sure directory exists with proper permissions.

    :param directory: Path to a directry.
    :type directory: str

    :param mode: Diretory mode.
    :type mode: int

    :param uid: Directory owner.
    :type uid: int

    :raises LetsEncryptClientError: if a directory already exists,
        but has wrong permissions or owner

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if not check_permissions(directory, mode, uid):
                raise errors.LetsEncryptClientError(
                    '%s exists and does not contain the proper '
                    'permissions or owner' % directory)
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param filepath: Path to the tested file (or directory).
    :type filepath: str

    :param mode: Expected file mode.
    :type mode: int

    :param uid: Expected file owner.
    :type uid: int

    :returns: bool -- True if `mode` and `uid` match, False otherwise.

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def unique_file(name, mode=0o777):
    """Safely finds a unique file for writing only (by default).

    :param name: Prefeferred file name. Similar names will be tried,
                 if `name` already exists.
    :type name: str

    :param mode: Has the same meaning as the corresponding argument
                 to the built-in open() function.
    :type mode: int

    :returns: File handle opened for writing.
    :rtype: file

    """
    count = 1
    f_parsed = os.path.splitext(name)
    while 1:
        try:
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_RDWR, mode)
            return os.fdopen(fd, 'w')
        except OSError:
            pass
        name = f_parsed[0] + '_' + str(count) + f_parsed[1]
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

    :raises TypeError: if input is of incorrect type

    :returns: JOSE Base64 string.
    :rtype: str

    """
    if not isinstance(data, str):
        raise TypeError('argument should be str or bytearray')
    return base64.urlsafe_b64encode(data).rstrip('=')


def jose_b64decode(data):
    """JOSE Base64 decode.

    :param data: Base64 string to be decoded. If it's unicode, then
                 only ASCII characters are allowed.
    :type data: str or unicode

    :raises TypeError: if input is of incorrect type
    :raises ValueError: if unput is unicode with non-ASCII characters

    :returns: Decoded data.

    """
    if isinstance(data, unicode):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError(
                'unicode argument should contain only ASCII characters')
    elif not isinstance(data, str):
        raise TypeError('argument should be a str or unicode')

    return base64.urlsafe_b64decode(data + '=' * (4 - (len(data) % 4)))
