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


class MemoryHandlerTest(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.msg = 'hi there'
        self.stream = six.StringIO()

        stream_handler = logging.StreamHandler(self.stream)
        from certbot.log import MemoryHandler
        self.handler = MemoryHandler(stream_handler)
        self.logger.addHandler(self.handler)

    def test_flush(self):
        self._test_log_debug()
        self.handler.flush()
        self.assertEqual(self.stream.getvalue(), self.msg + '\n')

    def test_not_flushed(self):
        # By default, logging.ERROR messages and higher are flushed
        self.logger.critical(self.msg)
        self.assertEqual(self.stream.getvalue(), '')

    def test_target_reset(self):
        self._test_log_debug()

        new_stream = six.StringIO()
        stream_handler = logging.StreamHandler(new_stream)
        self.handler.setTarget(stream_handler)
        self.handler.flush()
        self.assertEqual(self.stream.getvalue(), '')
        self.assertEqual(new_stream.getvalue(), self.msg + '\n')

    def _test_log_debug(self):
        self.logger.debug(self.msg)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
