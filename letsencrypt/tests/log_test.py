"""Tests for letsencrypt.log."""
import logging
import unittest

import mock


class DialogHandlerTest(unittest.TestCase):

    def setUp(self):
        self.d = mock.MagicMock()

        from letsencrypt.log import DialogHandler
        self.handler = DialogHandler(height=2, width=6, d=self.d)
        self.handler.PADDING_HEIGHT = 2
        self.handler.PADDING_WIDTH = 4

    def test_adds_padding(self):
        self.handler.emit(logging.makeLogRecord({}))
        self.d.infobox.assert_called_once_with(mock.ANY, 4, 10)

    def test_args_in_msg_get_replaced(self):
        assert len('123456') <= self.handler.width
        self.handler.emit(logging.makeLogRecord(
            {'msg': '123%s', 'args': (456,)}))
        self.d.infobox.assert_called_once_with('123456', mock.ANY, mock.ANY)

    def test_wraps_nospace_is_greedy(self):
        assert len('1234567') > self.handler.width
        self.handler.emit(logging.makeLogRecord({'msg': '1234567'}))
        self.d.infobox.assert_called_once_with('123456\n7', mock.ANY, mock.ANY)

    def test_wraps_at_whitespace(self):
        assert len('123 567') > self.handler.width
        self.handler.emit(logging.makeLogRecord({'msg': '123 567'}))
        self.d.infobox.assert_called_once_with('123\n567', mock.ANY, mock.ANY)

    def test_only_last_lines_are_printed(self):
        assert len('a\nb\nc'.split()) > self.handler.height
        self.handler.emit(logging.makeLogRecord({'msg': 'a\n\nb\nc'}))
        self.d.infobox.assert_called_once_with('b\nc', mock.ANY, mock.ANY)

    def test_non_str(self):
        self.handler.emit(logging.makeLogRecord({'msg': {'foo': 'bar'}}))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
