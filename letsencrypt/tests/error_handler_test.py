"""Tests for letsencrypt.error_handler."""
import unittest

import mock


class ErrorHandlerTest(unittest.TestCase):
    """Tests for letsencrypt.error_handler."""

    def setUp(self):
        from letsencrypt import error_handler
        self.init_func = mock.MagicMock()
        self.error_handler = error_handler.ErrorHandler(self.init_func)

    def test_context_manager(self):
        try:
            with self.error_handler:
                raise ValueError
        except ValueError:
            pass
        self.init_func.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
