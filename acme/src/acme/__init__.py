"""ACME protocol implementation.

This module is an implementation of the `ACME protocol`_.

.. _`ACME protocol`: https://datatracker.ietf.org/doc/html/rfc8555

"""
import sys

# This code exists to keep backwards compatibility with people using acme.jose
# before it became the standalone josepy package.
#
# It is based on
# https://github.com/requests/requests/blob/1278ecdf71a312dc2268f3bfc0aabfab3c006dcf/requests/packages.py
import josepy as jose # noqa: F401

for mod in list(sys.modules):
    # This traversal is apparently necessary such that the identities are
    # preserved (acme.jose.* is josepy.*)
    if mod == 'josepy' or mod.startswith('josepy.'):
        sys.modules['acme.' + mod.replace('josepy', 'jose', 1)] = sys.modules[mod]
