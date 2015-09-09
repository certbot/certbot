"""Module for enhancement UI."""
import logging
import unittest

import mock

from letsencrypt import errors
from letsencrypt.display import util as display_util


class AskTest(unittest.TestCase):
    """Test the ask method."""
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @classmethod
    def _call(cls, enhancement):
        from letsencrypt.display.enhancements import ask
        return ask(enhancement)

    @mock.patch("letsencrypt.display.enhancements.util")
    def test_redirect(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 1)
        self.assertTrue(self._call("redirect"))

    def test_key_error(self):
        self.assertRaises(errors.Error, self._call, "unknown_enhancement")


class RedirectTest(unittest.TestCase):
    """Test the redirect_by_default method."""
    @classmethod
    def _call(cls):
        from letsencrypt.display.enhancements import redirect_by_default
        return redirect_by_default()

    @mock.patch("letsencrypt.display.enhancements.util")
    def test_secure(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 1)
        self.assertTrue(self._call())

    @mock.patch("letsencrypt.display.enhancements.util")
    def test_cancel(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 1)
        self.assertFalse(self._call())

    @mock.patch("letsencrypt.display.enhancements.util")
    def test_easy(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)
        self.assertFalse(self._call())


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
