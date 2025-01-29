"""Unit test for os module."""
import sys

import pytest

from certbot.compat import os


def test_forbidden_methods():
    # Checks for os module
    for method in ['chmod', 'chown', 'open', 'mkdir', 'makedirs', 'rename',
                   'replace', 'access', 'stat', 'fstat']:
        with pytest.raises(RuntimeError):
            getattr(os, method)()
    # Checks for os.path module
    for method in ['realpath']:
        with pytest.raises(RuntimeError):
            getattr(os.path, method)()


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
