"""Tests for certbot.plugins.util."""
import sys
from unittest import mock

import pytest

from certbot.compat import os
from unittest.mock import MagicMock


def test_get_prefix() -> None:
    from certbot.plugins.util import get_prefixes
    assert get_prefixes('/a/b/c') == \
        [os.path.normpath(path) for path in ['/a/b/c', '/a/b', '/a', '/']]
    assert get_prefixes('/') == [os.path.normpath('/')]
    assert get_prefixes('a') == ['a']


@mock.patch("certbot.plugins.util.logger.debug")
def test_path_surgery(mock_debug: MagicMock) -> None:
    from certbot.plugins.util import path_surgery
    all_path = {"PATH": "/usr/local/bin:/bin/:/usr/sbin/:/usr/local/sbin/"}
    with mock.patch.dict('os.environ', all_path):
        with mock.patch('certbot.util.exe_exists') as mock_exists:
            mock_exists.return_value = True
            assert path_surgery("eg") is True
            assert mock_debug.call_count == 0
            assert os.environ["PATH"] == all_path["PATH"]
    if os.name != 'nt':
        # This part is specific to Linux since on Windows no PATH surgery is ever done.
        no_path = {"PATH": "/tmp/"}
        with mock.patch.dict('os.environ', no_path):
            path_surgery("thingy")
            assert mock_debug.call_count == (2 if os.name != 'nt' else 1)
            assert "Failed to find" in mock_debug.call_args[0][0]
            assert "/usr/local/bin" in os.environ["PATH"]
            assert "/tmp" in os.environ["PATH"]


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
