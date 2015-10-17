"""Tests for letsencrypt.plugins.util."""
import unittest

import mock
import psutil


class AlreadyListeningTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.already_listening."""
    def _call(self, *args, **kwargs):
        from letsencrypt.plugins.util import already_listening
        return already_listening(*args, **kwargs)

    @mock.patch("letsencrypt.plugins.util.psutil.net_connections")
    @mock.patch("letsencrypt.plugins.util.psutil.Process")
    @mock.patch("letsencrypt.plugins.util.zope.component.getUtility")
    def test_race_condition(self, mock_get_utility, mock_process, mock_net):
        # This tests a race condition, or permission problem, or OS
        # incompatibility in which, for some reason, no process name can be
        # found to match the identified listening PID.
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("0.0.0.0", 17),
                  raddr=(), status="LISTEN", pid=4416)]
        mock_net.return_value = conns
        mock_process.side_effect = psutil.NoSuchProcess("No such PID")
        # We simulate being unable to find the process name of PID 4416,
        # which results in returning False.
        self.assertFalse(self._call(17))
        self.assertEqual(mock_get_utility.generic_notification.call_count, 0)
        mock_process.assert_called_once_with(4416)

    @mock.patch("letsencrypt.plugins.util.psutil.net_connections")
    @mock.patch("letsencrypt.plugins.util.psutil.Process")
    @mock.patch("letsencrypt.plugins.util.zope.component.getUtility")
    def test_not_listening(self, mock_get_utility, mock_process, mock_net):
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None)]
        mock_net.return_value = conns
        mock_process.name.return_value = "inetd"
        self.assertFalse(self._call(17))
        self.assertEqual(mock_get_utility.generic_notification.call_count, 0)
        self.assertEqual(mock_process.call_count, 0)

    @mock.patch("letsencrypt.plugins.util.psutil.net_connections")
    @mock.patch("letsencrypt.plugins.util.psutil.Process")
    @mock.patch("letsencrypt.plugins.util.zope.component.getUtility")
    def test_listening_ipv4(self, mock_get_utility, mock_process, mock_net):
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("0.0.0.0", 17),
                  raddr=(), status="LISTEN", pid=4416)]
        mock_net.return_value = conns
        mock_process.name.return_value = "inetd"
        result = self._call(17)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        mock_process.assert_called_once_with(4416)

    @mock.patch("letsencrypt.plugins.util.psutil.net_connections")
    @mock.patch("letsencrypt.plugins.util.psutil.Process")
    @mock.patch("letsencrypt.plugins.util.zope.component.getUtility")
    def test_listening_ipv6(self, mock_get_utility, mock_process, mock_net):
        from psutil._common import sconn
        conns = [
            sconn(fd=-1, family=2, type=1, laddr=("0.0.0.0", 30),
                  raddr=(), status="LISTEN", pid=None),
            sconn(fd=3, family=2, type=1, laddr=("192.168.5.10", 32783),
                  raddr=("20.40.60.80", 22), status="ESTABLISHED", pid=1234),
            sconn(fd=-1, family=10, type=1, laddr=("::1", 54321),
                  raddr=("::1", 111), status="CLOSE_WAIT", pid=None),
            sconn(fd=3, family=10, type=1, laddr=("::", 12345), raddr=(),
                  status="LISTEN", pid=4420),
            sconn(fd=3, family=2, type=1, laddr=("0.0.0.0", 17),
                  raddr=(), status="LISTEN", pid=4416)]
        mock_net.return_value = conns
        mock_process.name.return_value = "inetd"
        result = self._call(12345)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        mock_process.assert_called_once_with(4420)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
