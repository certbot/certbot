"""Tests for certbot.plugins.util."""
import os
import unittest
import sys

import mock
from six.moves import reload_module  # pylint: disable=import-error

from certbot.tests import test_util


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


class AlreadyListeningTestNoPsutil(unittest.TestCase):
    """Tests for certbot.plugins.already_listening when
    psutil is not available"""
    def setUp(self):
        import certbot.plugins.util
        # Ensure we get importerror
        self.psutil = None
        if "psutil" in sys.modules:
            self.psutil = sys.modules['psutil']
        sys.modules['psutil'] = None
        # Reload hackery to ensure getting non-psutil version
        # loaded to memory
        reload_module(certbot.plugins.util)

    def tearDown(self):
        # Need to reload the module to ensure
        # getting back to normal
        import certbot.plugins.util
        sys.modules["psutil"] = self.psutil
        reload_module(certbot.plugins.util)

    @mock.patch("certbot.plugins.util.zope.component.getUtility")
    def test_ports_available(self, mock_getutil):
        import certbot.plugins.util as plugins_util
        # Ensure we don't get error
        with mock.patch("socket.socket.bind"):
            self.assertFalse(plugins_util.already_listening(80))
            self.assertFalse(plugins_util.already_listening(80, True))
            self.assertEqual(mock_getutil.call_count, 0)

    @mock.patch("certbot.plugins.util.zope.component.getUtility")
    def test_ports_blocked(self, mock_getutil):
        sys.modules["psutil"] = None
        import certbot.plugins.util as plugins_util
        import socket
        with mock.patch("socket.socket.bind", side_effect=socket.error):
            self.assertTrue(plugins_util.already_listening(80))
            self.assertTrue(plugins_util.already_listening(80, True))
        with mock.patch("socket.socket", side_effect=socket.error):
            self.assertFalse(plugins_util.already_listening(80))
        self.assertEqual(mock_getutil.call_count, 2)


def psutil_available():
    """Checks if psutil can be imported.

    :rtype: bool
    :returns: ``True`` if psutil can be imported, otherwise, ``False``

    """
    try:
        import psutil  # pylint: disable=unused-variable
    except ImportError:
        return False
    return True


@test_util.skip_unless(psutil_available(),
                       "optional dependency psutil is not available")
class AlreadyListeningTestPsutil(unittest.TestCase):
    """Tests for certbot.plugins.already_listening."""
    def _call(self, *args, **kwargs):
        from certbot.plugins.util import already_listening
        return already_listening(*args, **kwargs)

    @mock.patch("certbot.plugins.util.psutil.net_connections")
    @mock.patch("certbot.plugins.util.psutil.Process")
    @mock.patch("certbot.plugins.util.zope.component.getUtility")
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
    @mock.patch("certbot.plugins.util.zope.component.getUtility")
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
    @mock.patch("certbot.plugins.util.zope.component.getUtility")
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
    @mock.patch("certbot.plugins.util.zope.component.getUtility")
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
