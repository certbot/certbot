"""Tests for letsencrypt.notify."""
import socket
import unittest

import mock


class NotifyTests(unittest.TestCase):
    """Tests for the notifier."""

    @mock.patch("letsencrypt.notify.smtplib.LMTP")
    def test_smtp_success(self, mock_lmtp):
        from letsencrypt.notify import notify
        lmtp_obj = mock.MagicMock()
        mock_lmtp.return_value = lmtp_obj
        self.assertTrue(notify("Goose", "auntrhody@example.com",
                               "The old grey goose is dead."))
        self.assertEqual(lmtp_obj.connect.call_count, 1)
        self.assertEqual(lmtp_obj.sendmail.call_count, 1)

    @mock.patch("letsencrypt.notify.smtplib.LMTP")
    @mock.patch("letsencrypt.notify.subprocess.Popen")
    def test_smtp_failure(self, mock_popen, mock_lmtp):
        from letsencrypt.notify import notify
        lmtp_obj = mock.MagicMock()
        mock_lmtp.return_value = lmtp_obj
        lmtp_obj.sendmail.side_effect = socket.error(17)
        proc = mock.MagicMock()
        mock_popen.return_value = proc
        self.assertTrue(notify("Goose", "auntrhody@example.com",
                               "The old grey goose is dead."))
        self.assertEqual(lmtp_obj.sendmail.call_count, 1)
        self.assertEqual(proc.communicate.call_count, 1)

    @mock.patch("letsencrypt.notify.smtplib.LMTP")
    @mock.patch("letsencrypt.notify.subprocess.Popen")
    def test_everything_fails(self, mock_popen, mock_lmtp):
        from letsencrypt.notify import notify
        lmtp_obj = mock.MagicMock()
        mock_lmtp.return_value = lmtp_obj
        lmtp_obj.sendmail.side_effect = socket.error(17)
        proc = mock.MagicMock()
        mock_popen.return_value = proc
        proc.communicate.side_effect = OSError("What we have here is a "
                                               "failure to communicate.")
        self.assertFalse(notify("Goose", "auntrhody@example.com",
                                "The old grey goose is dead."))
        self.assertEqual(lmtp_obj.sendmail.call_count, 1)
        self.assertEqual(proc.communicate.call_count, 1)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
