"""ACME protocol implementation.

This module is an implementation of the `ACME protocol`_.

.. _`ACME protocol`: https://ietf-wg-acme.github.io/acme

"""
import sys
import warnings

# This code exists to keep backwards compatibility with people using acme.jose
# before it became the standalone josepy package.
#
# It is based on
# https://github.com/requests/requests/blob/1278ecdf71a312dc2268f3bfc0aabfab3c006dcf/requests/packages.py

import josepy as jose

for mod in list(sys.modules):
    # This traversal is apparently necessary such that the identities are
    # preserved (acme.jose.* is josepy.*)
    if mod == 'josepy' or mod.startswith('josepy.'):
        sys.modules['acme.' + mod.replace('josepy', 'jose', 1)] = sys.modules[mod]


# This class takes a similar approach to the cryptography project to deprecate attributes
# in public modules. See the _ModuleWithDeprecation class here:
# https://github.com/pyca/cryptography/blob/91105952739442a74582d3e62b3d2111365b0dc7/src/cryptography/utils.py#L129
class _TLSSNI01DeprecationModule(object):
    """
    Internal class delegating to a module, and displaying warnings when
    attributes related to TLS-SNI-01 are accessed.
    """
    def __init__(self, module):
        self.__dict__['_module'] = module

    def __getattr__(self, attr):
        if 'TLSSNI01' in attr:
            warnings.warn('{0} attribute is deprecated, and will be removed soon.'.format(attr),
                          DeprecationWarning, stacklevel=2)
        return getattr(self._module, attr)

    def __setattr__(self, attr, value):  # pragma: no cover
        setattr(self._module, attr, value)

    def __delattr__(self, attr):  # pragma: no cover
        delattr(self._module, attr)

    def __dir__(self):  # pragma: no cover
        return ['_module'] + dir(self._module)
