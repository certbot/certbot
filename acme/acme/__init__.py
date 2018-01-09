"""ACME protocol implementation.

This module is an implementation of the `ACME protocol`_. Latest
supported version: `draft-ietf-acme-01`_.


.. _`ACME protocol`: https://ietf-wg-acme.github.io/acme

.. _`draft-ietf-acme-01`:
  https://github.com/ietf-wg-acme/acme/tree/draft-ietf-acme-acme-01

"""
import sys
import warnings

for (major, minor) in [(2, 6), (3, 3)]:
    if sys.version_info[:2] == (major, minor):
        warnings.warn(
                "Python {0}.{1} support will be dropped in the next release of "
                "acme. Please upgrade your Python version.".format(major, minor),
                DeprecationWarning,
        ) #pragma: no cover
