"""Tests for certbot.log."""
import logging
import unittest

import six

from certbot import util


class ColoredStreamHandlerTest(unittest.TestCase):
    """Tests for certbot.log."""

    def setUp(self):
        from certbot import log

        self.stream = six.StringIO()
        self.stream.isatty = lambda: True
        self.handler = log.ColoredStreamHandler(self.stream)

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(self.handler)

    def test_format(self):
        msg = 'I did a thing'
        self.logger.debug(msg)
        self.assertEqual(self.stream.getvalue(), '{0}\n'.format(msg))

    def test_format_and_red_level(self):
        msg = 'I did another thing'
        self.handler.red_level = logging.DEBUG
        self.logger.debug(msg)

        self.assertEqual(self.stream.getvalue(),
                         '{0}{1}{2}\n'.format(util.ANSI_SGR_RED,
                                              msg,
                                              util.ANSI_SGR_RESET))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
