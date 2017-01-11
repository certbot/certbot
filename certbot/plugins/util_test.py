"""Tests for certbot.plugins.util."""
import os
import socket
import unittest

import mock

from certbot.plugins.util import PSUTIL_REQUIREMENT
from certbot.tests import util as test_util


class PathSurgeryTest(unittest.TestCase):
    """Tests for certbot.plugins.path_surgery."""

    @mock.patch("certbot.plugins.util.logger.warning")
    @mock.patch("certbot.plugins.util.logger.debug")
    def test_path_surgery(self, mock_debug, mock_warn):
        from certbot.plugins.util import path_surgery
        all_path = {"PATH": "/usr/local/bin:/bin/:/usr/sbin/:/usr/local/sbin/"}
        with mock.patch.dict('os.environ', all_path):
            with mock.patch('certbot.util.exe_exists') as mock_exists:
                mock_exists.return_value = True
                self.assertEqual(path_surgery("eg"), True)
                self.assertEqual(mock_debug.call_count, 0)
                self.assertEqual(mock_warn.call_count, 0)
                self.assertEqual(os.environ["PATH"], all_path["PATH"])
        no_path = {"PATH": "/tmp/"}
        with mock.patch.dict('os.environ', no_path):
            path_surgery("thingy")
            self.assertEqual(mock_debug.call_count, 1)
            self.assertEqual(mock_warn.call_count, 1)
            self.assertTrue("Failed to find" in mock_warn.call_args[0][0])
            self.assertTrue("/usr/local/bin" in os.environ["PATH"])
            self.assertTrue("/tmp" in os.environ["PATH"])


class AlreadyListeningTest(unittest.TestCase):
    """Tests for certbot.plugins.already_listening."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.plugins.util import already_listening
        return already_listening(*args, **kwargs)


class AlreadyListeningTestNoPsutil(AlreadyListeningTest):
    """Tests for certbot.plugins.already_listening when
    psutil is not available"""
    @classmethod
    def _call(cls, *args, **kwargs):
        with mock.patch("certbot.plugins.util.USE_PSUTIL", False):
            return super(
                AlreadyListeningTestNoPsutil, cls)._call(*args, **kwargs)

    @test_util.patch_get_utility()
    def test_ports_available(self, mock_getutil):
        # Ensure we don't get error
        with mock.patch("socket.socket.bind"):
            self.assertFalse(self._call(80))
            self.assertFalse(self._call(80, True))
            self.assertEqual(mock_getutil.call_count, 0)

    @test_util.patch_get_utility()
    def test_ports_blocked(self, mock_getutil):
        with mock.patch("certbot.plugins.util.socket.socket.bind") as mock_bind:
            mock_bind.side_effect = socket.error
            self.assertTrue(self._call(80))
            self.assertTrue(self._call(80, True))
        with mock.patch("certbot.plugins.util.socket.socket") as mock_socket:
            mock_socket.side_effect = socket.error
            self.assertFalse(self._call(80))
        self.assertEqual(mock_getutil.call_count, 2)


@test_util.skip_unless(test_util.requirement_available(PSUTIL_REQUIREMENT),
                       "optional dependency psutil is not available")
class AlreadyListeningTestPsutil(AlreadyListeningTest):
    """Tests for certbot.plugins.already_listening."""
    @mock.patch("certbot.plugins.util.psutil.net_connections")
    @mock.patch("certbot.plugins.util.psutil.Process")
    @test_util.patch_get_utility()
    def test_race_condition(self, mock_get_utility, mock_process, mock_net):
        # This tests a race condition, or permission problem, or OS
        # incompatibility in which, for some reason, no process name can be
        # found to match the identified listening PID.
        import psutil
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

    @mock.patch("certbot.plugins.util.psutil.net_connections")
    @mock.patch("certbot.plugins.util.psutil.Process")
    @test_util.patch_get_utility()
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

    @mock.patch("certbot.plugins.util.psutil.net_connections")
    @mock.patch("certbot.plugins.util.psutil.Process")
    @test_util.patch_get_utility()
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
        result = self._call(17, True)
        self.assertTrue(result)
        self.assertEqual(mock_get_utility.call_count, 1)
        mock_process.assert_called_once_with(4416)

    @mock.patch("certbot.plugins.util.psutil.net_connections")
    @mock.patch("certbot.plugins.util.psutil.Process")
    @test_util.patch_get_utility()
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

    @mock.patch("certbot.plugins.util.psutil.net_connections")
    def test_access_denied_exception(self, mock_net):
        import psutil
        mock_net.side_effect = psutil.AccessDenied("")
        self.assertFalse(self._call(12345))

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
