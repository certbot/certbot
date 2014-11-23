"""Utilities for all Let's Encrypt."""
import base64
import errno
import os
import stat


def make_or_verify_dir(directory, mode=0755, uid=0):
    """Make sure directory exists with proper permissions.

    :param directory: Path to a directry.
    :type directory: str

    :param mode: Diretory mode.
    :type mode: int

    :param uid: Directory owner.
    :type uid: int

    :raises: Exception -- TODO

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if not check_permissions(directory, mode, uid):
                raise Exception('%s exists and does not contain the proper '
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


def unique_file(default_name, mode=0777):
    """Safely finds a unique file for writing only (by default)."""
    count = 1
    f_parsed = os.path.splitext(default_name)
    while 1:
        try:
            fd = os.open(
                default_name, os.O_CREAT | os.O_EXCL | os.O_RDWR, mode)
            return os.fdopen(fd, 'w'), default_name
        except OSError:
            pass
        default_name = f_parsed[0] + '_' + str(count) + f_parsed[1]
        count += 1


# https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#appendix-C
#
# Jose Base64:
#
#   - URL-safe Base64
#
#   - padding stripped


def jose_b64encode(data, encoding='utf-8'):
    """JOSE Base64 encode.

    :param data: Data to be encoded.
    :type data: str or unicode

    :param encoding: Name of the encoding to be performed before
                     Base64 encoding. If not None, then `data`
                     has to be unicode.
    :type encoding: str or None

    :returns: JOSE Base64 string.
    :rtype: str

    """
    encoded = data if encoding is None else data.encode(encoding)
    return base64.urlsafe_b64encode(encoded).rstrip('=')


def jose_b64decode(arg, decoding='utf-8'):
    """JOSE Base64 decode.

    :param arg: Base64 string to be decoded.
    :type arg: str

    :param decoding: Name of the encoding to be performed after
                     Base64 decoding.
    :type decoding: str or None

    :returns: Decoded data. Unicode if `decoding` is not None.
    :rtype: str or unicode

    """
    decoded = base64.urlsafe_b64decode(arg + '=' * (4 - (len(arg) % 4)))
    return decoded if decoding is None else decoded.decode(decoding)
