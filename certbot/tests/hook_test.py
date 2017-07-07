"""Tests for hooks.py"""
# pylint: disable=protected-access

import os
import unittest

import mock
from six.moves import reload_module  # pylint: disable=import-error

from certbot import errors
from certbot import hooks

class HookTest(unittest.TestCase):
    def setUp(self):
        reload_module(hooks)

    @mock.patch('certbot.hooks._prog')
    def test_validate_hooks(self, mock_prog):
        config = mock.MagicMock(deploy_hook=None, pre_hook="",
                                post_hook="ls -lR", renew_hook="uptime")
        hooks.validate_hooks(config)
        self.assertEqual(mock_prog.call_count, 2)
        self.assertEqual(mock_prog.call_args_list[1][0][0], 'uptime')
        self.assertEqual(mock_prog.call_args_list[0][0][0], 'ls')
        mock_prog.return_value = None
        config = mock.MagicMock(pre_hook="explodinator", post_hook="", renew_hook="")
        self.assertRaises(errors.HookCommandNotFound, hooks.validate_hooks, config)

    @mock.patch('certbot.hooks.validate_hook')
    def test_validation_order(self, mock_validate_hook):
        # This ensures error messages are about deploy hook when appropriate
        config = mock.Mock(deploy_hook=None, pre_hook=None,
                           post_hook=None, renew_hook=None)
        hooks.validate_hooks(config)

        order = [call[0][1] for call in mock_validate_hook.call_args_list]
        self.assertTrue('pre' in order)
        self.assertTrue('post' in order)
        self.assertTrue('deploy' in order)
        self.assertEqual(order[-1], 'renew')

    @mock.patch('certbot.hooks.util.exe_exists')
    @mock.patch('certbot.hooks.plug_util.path_surgery')
    def test_prog(self, mock_ps, mock_exe_exists):
        mock_exe_exists.return_value = True
        self.assertEqual(hooks._prog("funky"), "funky")
        self.assertEqual(mock_ps.call_count, 0)
        mock_exe_exists.return_value = False
        self.assertEqual(hooks._prog("funky"), None)
        self.assertEqual(mock_ps.call_count, 1)

    @mock.patch('certbot.hooks.renew_hook')
    def test_deploy_hook(self, mock_renew_hook):
        args = (mock.Mock(deploy_hook='foo'), ['example.org'], 'path',)
        # pylint: disable=star-args
        hooks.deploy_hook(*args)
        mock_renew_hook.assert_called_once_with(*args)

    @mock.patch('certbot.hooks.renew_hook')
    def test_no_deploy_hook(self, mock_renew_hook):
        args = (mock.Mock(deploy_hook=None), ['example.org'], 'path',)
        hooks.deploy_hook(*args)  # pylint: disable=star-args
        mock_renew_hook.assert_not_called()

    def _test_a_hook(self, config, hook_function, calls_expected, **kwargs):
        with mock.patch('certbot.hooks.logger') as mock_logger:
            mock_logger.warning = mock.MagicMock()
            with mock.patch('certbot.hooks._run_hook') as mock_run_hook:
                hook_function(config, **kwargs)
                hook_function(config, **kwargs)
                self.assertEqual(mock_run_hook.call_count, calls_expected)
            return mock_logger.warning

    def test_pre_hook(self):
        config = mock.MagicMock(pre_hook="true")
        self._test_a_hook(config, hooks.pre_hook, 1)
        self._test_a_hook(config, hooks.pre_hook, 0)
        config = mock.MagicMock(pre_hook="more_true")
        self._test_a_hook(config, hooks.pre_hook, 1)
        self._test_a_hook(config, hooks.pre_hook, 0)
        config = mock.MagicMock(pre_hook="")
        self._test_a_hook(config, hooks.pre_hook, 0)

    def _test_renew_post_hooks(self, expected_count):
        with mock.patch('certbot.hooks.logger.info') as mock_info:
            with mock.patch('certbot.hooks._run_hook') as mock_run:
                hooks.run_saved_post_hooks()
                self.assertEqual(mock_run.call_count, expected_count)
                self.assertEqual(mock_info.call_count, expected_count)

    def test_post_hooks(self):
        config = mock.MagicMock(post_hook="true", verb="splonk")
        self._test_a_hook(config, hooks.post_hook, 2)
        self._test_renew_post_hooks(0)

        config = mock.MagicMock(post_hook="true", verb="renew")
        self._test_a_hook(config, hooks.post_hook, 0)
        self._test_renew_post_hooks(1)
        self._test_a_hook(config, hooks.post_hook, 0)
        self._test_renew_post_hooks(1)

        config = mock.MagicMock(post_hook="more_true", verb="renew")
        self._test_a_hook(config, hooks.post_hook, 0)
        self._test_renew_post_hooks(2)

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
