"""JOSE Base64.

`JOSE Base64`_ is defined as:

  - URL-safe Base64
  - padding stripped


.. _`JOSE Base64`:
    https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-37#appendix-C

.. Do NOT try to call this module "base64", as it will "shadow" the
   standard library.

"""
import base64

import six


def b64encode(data):
    """JOSE Base64 encode.

    :param data: Data to be encoded.
    :type data: `bytes`

    :returns: JOSE Base64 string.
    :rtype: bytes

    :raises TypeError: if `data` is of incorrect type

    """
    if not isinstance(data, six.binary_type):
        raise TypeError('argument should be {0}'.format(six.binary_type))
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def b64decode(data):
    """JOSE Base64 decode.

    :param data: Base64 string to be decoded. If it's unicode, then
                 only ASCII characters are allowed.
    :type data: `bytes` or `unicode`

    :returns: Decoded data.
    :rtype: bytes

    :raises TypeError: if input is of incorrect type
    :raises ValueError: if input is unicode with non-ASCII characters

    """
    if isinstance(data, six.string_types):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError(
                'unicode argument should contain only ASCII characters')
    elif not isinstance(data, six.binary_type):
        raise TypeError('argument should be a str or unicode')

    return base64.urlsafe_b64decode(data + b'=' * (4 - (len(data) % 4)))
