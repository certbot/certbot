"""Tests for hooks.py"""
# pylint: disable=protected-access

import os
import unittest

import mock

from certbot import errors
from certbot import hooks

class HookTest(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch('certbot.hooks._prog')
    def test_validate_hooks(self, mock_prog):
        config = mock.MagicMock(pre_hook="", post_hook="ls -lR", renew_hook="uptime")
        hooks.validate_hooks(config)
        self.assertEqual(mock_prog.call_count, 2)
        self.assertEqual(mock_prog.call_args_list[1][0][0], 'uptime')
        self.assertEqual(mock_prog.call_args_list[0][0][0], 'ls')
        mock_prog.return_value = None
        config = mock.MagicMock(pre_hook="explodinator", post_hook="", renew_hook="")
        self.assertRaises(errors.HookCommandNotFound, hooks.validate_hooks, config)

    @mock.patch('certbot.hooks._is_exe')
    def test_which(self, mock_is_exe):
        mock_is_exe.return_value = True
        self.assertEqual(hooks._which("/path/to/something"), "/path/to/something")

        with mock.patch.dict('os.environ', {"PATH": "/floop:/fleep"}):
            mock_is_exe.return_value = True
            self.assertEqual(hooks._which("pingify"), "/floop/pingify")
            mock_is_exe.return_value = False
            self.assertEqual(hooks._which("pingify"), None)
        self.assertEqual(hooks._which("/path/to/something"), None)

    @mock.patch('certbot.hooks._which')
    def test_prog(self, mockwhich):
        mockwhich.return_value = "/very/very/funky"
        self.assertEqual(hooks._prog("funky"), "funky")
        mockwhich.return_value = None
        self.assertEqual(hooks._prog("funky"), None)

    def _test_a_hook(self, config, hook_function, calls_expected):
        with mock.patch('certbot.hooks.logger') as mock_logger:
            mock_logger.warning = mock.MagicMock()
            with mock.patch('certbot.hooks._run_hook') as mock_run_hook:
                hook_function(config)
                hook_function(config)
                self.assertEqual(mock_run_hook.call_count, calls_expected)
            return mock_logger.warning

    def test_pre_hook(self):
        hooks.pre_hook.already = False
        config = mock.MagicMock(pre_hook="true")
        self._test_a_hook(config, hooks.pre_hook, 1)
        config = mock.MagicMock(pre_hook="")
        self._test_a_hook(config, hooks.pre_hook, 0)

    def test_post_hook(self):
        hooks.pre_hook.already = False
        # if pre-hook isn't called, post-hook shouldn't be
        config = mock.MagicMock(post_hook="true", verb="splonk")
        self._test_a_hook(config, hooks.post_hook, 0)

        config = mock.MagicMock(post_hook="true", verb="splonk")
        self._test_a_hook(config, hooks.pre_hook, 1)
        self._test_a_hook(config, hooks.post_hook, 2)

        config = mock.MagicMock(post_hook="true", verb="renew")
        self._test_a_hook(config, hooks.post_hook, 0)

    def test_renew_hook(self):
        with mock.patch.dict('os.environ', {}):
            domains = ["a", "b"]
            lineage = "thing"
            rhook = lambda x: hooks.renew_hook(x, domains, lineage)

            config = mock.MagicMock(renew_hook="true", dry_run=False)
            self._test_a_hook(config, rhook, 2)
            self.assertEqual(os.environ["RENEWED_DOMAINS"], "a b")
            self.assertEqual(os.environ["RENEWED_LINEAGE"], "thing")

            config = mock.MagicMock(renew_hook="true", dry_run=True)
            mock_warn = self._test_a_hook(config, rhook, 0)
            self.assertEqual(mock_warn.call_count, 2)

    @mock.patch('certbot.hooks.Popen')
    def test_run_hook(self, mock_popen):
        with mock.patch('certbot.hooks.logger.error') as mock_error:
            mock_cmd = mock.MagicMock()
            mock_cmd.returncode = 1
            mock_cmd.communicate.return_value = ("", "")
            mock_popen.return_value = mock_cmd
            hooks._run_hook("ls")
            self.assertEqual(mock_error.call_count, 1)
        with mock.patch('certbot.hooks.logger.error') as mock_error:
            mock_cmd.communicate.return_value = ("", "thing")
            hooks._run_hook("ls")
            self.assertEqual(mock_error.call_count, 2)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
