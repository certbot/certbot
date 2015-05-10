"""JOSE Base64.

`JOSE Base64`_ is defined as:

  - URL-safe Base64
  - padding stripped


.. _`JOSE Base64`:
    https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#appendix-C

.. warning:: Do NOT try to call this module "base64",
    as it will "shadow" the standard library.

"""
import base64


def b64encode(data):
    """JOSE Base64 encode.

    :param data: Data to be encoded.
    :type data: str or bytearray

    :returns: JOSE Base64 string.
    :rtype: str

    :raises TypeError: if `data` is of incorrect type

    """
    if not isinstance(data, str):
        raise TypeError('argument should be str or bytearray')
    return base64.urlsafe_b64encode(data).rstrip('=')


def b64decode(data):
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
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError(
                'unicode argument should contain only ASCII characters')
    elif not isinstance(data, str):
        raise TypeError('argument should be a str or unicode')

    return base64.urlsafe_b64decode(data + '=' * (4 - (len(data) % 4)))
