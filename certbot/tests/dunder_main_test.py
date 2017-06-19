"""Tests for certbot.__main__."""
import unittest

import mock


class MainTest(unittest.TestCase):
    """Tests for certbot.__main__.main."""

    def test_failure(self):
        self._test_helper('error message')

    def test_success(self):
        self._test_helper(None)

    def _test_helper(self, return_value):
        with mock.patch('certbot.__main__.logger') as mock_logger:
            with mock.patch('certbot.main.main') as mock_certbot_main:
                mock_certbot_main.return_value = return_value
                with mock.patch('sys.exit') as mock_exit:
                    from certbot.__main__ import main
                    main()

        mock_certbot_main.assert_called_once_with()
        if return_value:
            self.assertTrue(mock_logger.debug.called)
        mock_exit.assert_called_once_with(return_value)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
