"""Tests for certbot._internal.plugins.apache.constants"""
import sys
import os.path

import pytest

from certbot._internal.plugins.apache import constants


def test_augeas_lens_dir_exists():
    assert os.path.exists(constants.AUGEAS_LENS_DIR)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
