"""ACME protocol implementation.

This module is an implementation of the `ACME protocol`_. Latest
supported version: `draft-ietf-acme-01`_.


.. _`ACME protocol`: https://ietf-wg-acme.github.io/acme

.. _`draft-ietf-acme-01`:
  https://github.com/ietf-wg-acme/acme/tree/draft-ietf-acme-acme-01

"""
import sys

import josepy

# This code exists to keep backwards compatibility with people using acme.jose
# before it became the standalone josepy package.
#
# It is based on
# https://github.com/requests/requests/blob/1278ecdf71a312dc2268f3bfc0aabfab3c006dcf/requests/packages.py

for mod in list(sys.modules):
    # This traversal is apparently necessary such that the identities are
    # preserved (acme.jose.* is josepy.*)
    if mod == 'josepy' or mod.startswith('josepy.'):
        sys.modules['acme.' + mod.replace('josepy', 'jose', 1)] = sys.modules[mod]
