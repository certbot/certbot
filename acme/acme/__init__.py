"""ACME protocol implementation.

This module is an implementation of the `ACME protocol`_. Latest
supported version: `draft-ietf-acme-01`_.


.. _`ACME protocol`: https://ietf-wg-acme.github.io/acme

.. _`draft-ietf-acme-01`:
  https://github.com/ietf-wg-acme/acme/tree/draft-ietf-acme-acme-01

"""
import sys
import warnings

if sys.version_info[:2] == (3, 3):
    warnings.warn(
            "Python 3.3 support will be dropped in the next release of "
            "acme. Please upgrade your Python version.",
            PendingDeprecationWarning,
    ) #pragma: no cover
