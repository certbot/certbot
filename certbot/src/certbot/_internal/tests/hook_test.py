"""Tests for certbot._internal.hooks."""
import sys
import unittest
from platform import python_version_tuple
from unittest import mock

import pytest

from certbot import errors
from certbot import util
from certbot.compat import filesystem
from certbot.compat import os
from certbot.tests import util as test_util


def pyver_lt(major: int, minor: int):
    pymajor = int(python_version_tuple()[0])
    pyminor = int(python_version_tuple()[1])
    if pymajor < major:
        return True
    elif pymajor > major:
        return False
    else:
        return pyminor < minor


class ValidateHooksTest(unittest.TestCase):
    """Tests for certbot._internal.hooks.validate_hooks."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import validate_hooks
        return validate_hooks(*args, **kwargs)

    @mock.patch("certbot._internal.hooks.validate_hook")
    def test_it(self, mock_validate_hook):
        config = mock.MagicMock()
        self._call(config)

        types = [call[0][1] for call in mock_validate_hook.call_args_list]
        assert {"pre", "post", "deploy",} == set(types[:-1])
        # This ensures error messages are about deploy hooks when appropriate
        assert "renew" == types[-1]


class ValidateHookTest(test_util.TempDirTestCase):
    """Tests for certbot._internal.hooks.validate_hook."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import validate_hook
        return validate_hook(*args, **kwargs)

    def test_hook_not_executable(self):
        # prevent unnecessary modifications to PATH
        with mock.patch("certbot._internal.hooks.plug_util.path_surgery"):
            # We just mock out filesystem.is_executable since on Windows, it is difficult
            # to get a fully working test around executable permissions. See
            # certbot.tests.compat.filesystem::NotExecutableTest for more in-depth tests.
            with mock.patch("certbot._internal.hooks.filesystem.is_executable", return_value=False):
                with pytest.raises(errors.HookCommandNotFound):
                    self._call('dummy', "foo")

    @mock.patch("certbot._internal.hooks.util.exe_exists")
    def test_not_found(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        with mock.patch("certbot._internal.hooks.plug_util.path_surgery") as mock_ps:
            with pytest.raises(errors.HookCommandNotFound):
                self._call("foo", "bar")
        assert mock_ps.called

    @mock.patch("certbot._internal.hooks._prog")
    def test_unset(self, mock_prog):
        self._call(None, "foo")
        assert mock_prog.called is False


class HookTest(test_util.ConfigTestCase):
    """Common base class for hook tests."""

    @classmethod
    def _call(cls, *args, **kwargs):  # pragma: no cover
        """Calls the method being tested with the given arguments."""
        raise NotImplementedError

    @classmethod
    def _call_with_mock_execute(cls, *args, **kwargs):
        """Calls self._call after mocking out certbot.compat.misc.execute_command_status.

        The mock execute object is returned rather than the return value
        of self._call.

        """
        with mock.patch("certbot.compat.misc.execute_command_status") as mock_execute:
            mock_execute.return_value = (0, "", "")
            cls._call(*args, **kwargs)
        return mock_execute


class PreHookTest(HookTest):
    """Tests for certbot._internal.hooks.pre_hook."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import pre_hook
        return pre_hook(*args, **kwargs)

    def setUp(self):
        super().setUp()
        self.config.pre_hook = "foo"

        filesystem.makedirs(self.config.renewal_pre_hooks_dir)
        self.dir_hook = os.path.join(self.config.renewal_pre_hooks_dir, "bar")
        create_hook(self.dir_hook)

        # Reset this value as it may have been modified by past tests
        self._reset_pre_hook_already()

    def tearDown(self):
        # Reset this value so it's unmodified for future tests
        self._reset_pre_hook_already()
        super().tearDown()

    def _reset_pre_hook_already(self):
        from certbot._internal.hooks import executed_pre_hooks
        executed_pre_hooks.clear()

    def test_certonly(self):
        self.config.verb = "certonly"
        self._test_nonrenew_common()

    def test_run(self):
        self.config.verb = "run"
        self._test_nonrenew_common()

    def _test_nonrenew_common(self):
        mock_execute = self._call_with_mock_execute(self.config)
        mock_execute.assert_any_call("pre-hook", self.dir_hook, env=mock.ANY)
        mock_execute.assert_called_with("pre-hook", self.config.pre_hook, env=mock.ANY)
        self._test_no_executions_common()

    def test_no_hooks(self):
        self.config.pre_hook = None
        self.config.verb = "renew"
        os.remove(self.dir_hook)

        with mock.patch("certbot._internal.hooks.logger") as mock_logger:
            mock_execute = self._call_with_mock_execute(self.config)
        assert mock_execute.called is False
        assert mock_logger.info.called is False

    def test_renew_disabled_dir_hooks(self):
        self.config.directory_hooks = False
        mock_execute = self._call_with_mock_execute(self.config)
        mock_execute.assert_called_once_with("pre-hook", self.config.pre_hook, env=mock.ANY)
        self._test_no_executions_common()

    def test_renew_no_overlap(self):
        self.config.verb = "renew"
        mock_execute = self._call_with_mock_execute(self.config)
        mock_execute.assert_any_call("pre-hook", self.dir_hook, env=mock.ANY)
        mock_execute.assert_called_with("pre-hook", self.config.pre_hook, env=mock.ANY)
        self._test_no_executions_common()

    def test_renew_with_overlap(self):
        self.config.pre_hook = self.dir_hook
        self.config.verb = "renew"
        mock_execute = self._call_with_mock_execute(self.config)
        mock_execute.assert_called_once_with("pre-hook", self.dir_hook, env=mock.ANY)
        self._test_no_executions_common()

    def _test_no_executions_common(self):
        with mock.patch("certbot._internal.hooks.logger") as mock_logger:
            mock_execute = self._call_with_mock_execute(self.config)
        assert mock_execute.called is False
        assert mock_logger.info.called


class PostHookTest(HookTest):
    """Tests for certbot._internal.hooks.post_hook."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import post_hook
        return post_hook(*args, **kwargs)

    def setUp(self):
        super().setUp()

        self.config.post_hook = "bar"
        filesystem.makedirs(self.config.renewal_post_hooks_dir)
        self.dir_hook = os.path.join(self.config.renewal_post_hooks_dir, "foo")
        create_hook(self.dir_hook)

        # Reset this value as it may have been modified by past tests
        self._reset_post_hook_eventually()

    def tearDown(self):
        # Reset this value so it's unmodified for future tests
        self._reset_post_hook_eventually()
        super().tearDown()

    def _reset_post_hook_eventually(self):
        from certbot._internal.hooks import post_hooks
        del post_hooks[:]

    def test_certonly_and_run_with_hook(self):
        for verb in ("certonly", "run",):
            self.config.verb = verb
            mock_execute = self._call_with_mock_execute(self.config, [])
            mock_execute.assert_any_call("post-hook", self.dir_hook, env=mock.ANY)
            mock_execute.assert_called_with("post-hook", self.config.post_hook, env=mock.ANY)
            assert not self._get_eventually()

    def test_certonly_and_run_without_cli_hook(self):
        self.config.post_hook = None
        for verb in ("certonly", "run",):
            self.config.verb = verb
            mock_execute = self._call_with_mock_execute(self.config, [])
            mock_execute.assert_called_once_with("post-hook", self.dir_hook, env=mock.ANY)
            assert not self._get_eventually()

    def test_renew_env(self):
        self.config.verb = "certonly"
        args = self._call_with_mock_execute(self.config, ["success.org"]).call_args
        assert args.kwargs['env']["RENEWED_DOMAINS"] == "success.org"

    def test_renew_disabled_dir_hooks(self):
        self.config.directory_hooks = False
        self._test_renew_common([self.config.post_hook])

    def test_renew_no_config_hook(self):
        self.config.post_hook = None
        self._test_renew_common([self.dir_hook])

    def test_renew_no_dir_hook(self):
        os.remove(self.dir_hook)
        self._test_renew_common([self.config.post_hook])

    def test_renew_no_hooks(self):
        self.config.post_hook = None
        os.remove(self.dir_hook)
        self._test_renew_common([])

    def test_renew_no_overlap(self):
        expected = [self.dir_hook, self.config.post_hook]
        self._test_renew_common(expected)

        self.config.post_hook = "baz"
        expected.append(self.config.post_hook)
        self._test_renew_common(expected)

    def test_renew_with_overlap(self):
        self.config.post_hook = self.dir_hook
        self._test_renew_common([self.dir_hook])

    def _test_renew_common(self, expected):
        self.config.verb = "renew"

        for _ in range(2):
            self._call(self.config, [])
            assert self._get_eventually() == expected

    def _get_eventually(self):
        from certbot._internal.hooks import post_hooks
        return post_hooks


class RunSavedPostHooksTest(HookTest):
    """Tests for certbot._internal.hooks.run_saved_post_hooks."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import run_saved_post_hooks
        renewed_domains = kwargs["renewed_domains"] if "renewed_domains" in kwargs else args[0]
        failed_domains = kwargs["failed_domains"] if "failed_domains" in kwargs else args[1]

        return run_saved_post_hooks(renewed_domains, failed_domains)

    def _call_with_mock_execute_and_eventually(self, *args, **kwargs):
        """Call run_saved_post_hooks but mock out execute and eventually

        certbot._internal.hooks.post_hooks is replaced with
        self.eventually. The mock execute object is returned rather than
        the return value of run_saved_post_hooks.

        """
        eventually_path = "certbot._internal.hooks.post_hooks"
        with mock.patch(eventually_path, new=self.eventually):
            return self._call_with_mock_execute(*args, **kwargs)

    def setUp(self):
        super().setUp()
        self.eventually: list[str] = []

    def test_empty(self):
        assert not self._call_with_mock_execute_and_eventually([], []).called

    def test_multiple(self):
        self.eventually = ["foo", "bar", "baz", "qux"]
        mock_execute = self._call_with_mock_execute_and_eventually([], [])

        calls = mock_execute.call_args_list
        for actual_call, expected_arg in zip(calls, self.eventually):
            assert actual_call[0][1] == expected_arg

    def test_single(self):
        self.eventually = ["foo"]
        mock_execute = self._call_with_mock_execute_and_eventually([], [])
        mock_execute.assert_called_once_with("post-hook", self.eventually[0], env=mock.ANY)

    def test_env(self):
        self.eventually = ["foo"]
        mock_execute = self._call_with_mock_execute_and_eventually(["success.org"], ["failed.org"])
        assert mock_execute.call_args.kwargs['env']["RENEWED_DOMAINS"] == "success.org"
        assert mock_execute.call_args.kwargs['env']["FAILED_DOMAINS"] == "failed.org"


class RenewalHookTest(HookTest):
    """Common base class for testing deploy/renew hooks."""
    # Needed for https://github.com/PyCQA/pylint/issues/179
    # pylint: disable=abstract-method

    def _call_with_mock_execute(self, *args, **kwargs):
        """Calls self._call after mocking out certbot.compat.misc.execute_command_status.

        The mock execute object is returned rather than the return value
        of self._call. The mock execute object asserts that environment
        variables were properly set.

        """
        domains = kwargs["domains"] if "domains" in kwargs else args[1]
        lineage = kwargs["lineage"] if "lineage" in kwargs else args[2]

        def execute_side_effect(*unused_args, **unused_kwargs):
            """Assert environment variables are properly set.

            :returns: two strings imitating no output from the hook
            :rtype: `tuple` of `str`

            """
            assert os.environ["RENEWED_DOMAINS"] == " ".join(domains)
            assert os.environ["RENEWED_LINEAGE"] == lineage
            return (0, "", "")

        with mock.patch("certbot.compat.misc.execute_command_status") as mock_execute:
            mock_execute.side_effect = execute_side_effect
            self._call(*args, **kwargs)
        return mock_execute

    def setUp(self):
        super().setUp()
        self.vars_to_clear = {
            var for var in ("RENEWED_DOMAINS", "RENEWED_LINEAGE",)
            if var not in os.environ
        }

    def tearDown(self):
        for var in self.vars_to_clear:
            os.environ.pop(var, None)
        super().tearDown()


class DeployHookTest(RenewalHookTest):
    """Tests for certbot._internal.hooks.deploy_hook."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import deploy_hook
        return deploy_hook(*args, **kwargs)

    def setUp(self):
        super().setUp()
        self.config.deploy_hook = "foo" # also sets renew_hook

        filesystem.makedirs(self.config.renewal_deploy_hooks_dir)
        self.dir_hook = os.path.join(self.config.renewal_deploy_hooks_dir,
                                     "bar")
        create_hook(self.dir_hook)

    @mock.patch("certbot._internal.hooks.logger")
    def test_dry_run(self, mock_logger):
        self.config.deploy_hook = "foo" # also sets renew_hook
        self.config.dry_run = True
        mock_execute = self._call_with_mock_execute(
            self.config, ["example.org"], "/foo/bar")
        assert mock_execute.called is False
        assert mock_logger.info.called

    def test_no_hooks(self):
        self.config.renew_hook = None
        os.remove(self.dir_hook)

        with mock.patch("certbot._internal.hooks.logger") as mock_logger:
            mock_execute = self._call_with_mock_execute(
                self.config, ["example.org"], "/foo/bar")
        assert mock_execute.called is False
        assert mock_logger.info.called is False

    def test_success(self):
        domains = ["example.org", "example.net"]
        lineage = "/foo/bar"
        self.config.deploy_hook = "foo"
        mock_execute = self._call_with_mock_execute(
            self.config, domains, lineage)
        assert mock_execute.call_count == 2


class RenewHookTest(RenewalHookTest):
    """Tests for certbot._internal.hooks.renew_hook"""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import renew_hook
        return renew_hook(*args, **kwargs)

    def setUp(self):
        super().setUp()
        self.config.renew_hook = "foo"

        filesystem.makedirs(self.config.renewal_deploy_hooks_dir)
        self.dir_hook = os.path.join(self.config.renewal_deploy_hooks_dir,
                                     "bar")
        create_hook(self.dir_hook)

    def test_disabled_dir_hooks(self):
        self.config.directory_hooks = False
        mock_execute = self._call_with_mock_execute(
            self.config, ["example.org"], "/foo/bar")
        mock_execute.assert_called_once_with("deploy-hook", self.config.renew_hook, env=mock.ANY)

    @mock.patch("certbot._internal.hooks.logger")
    def test_dry_run(self, mock_logger):
        self.config.dry_run = True
        mock_execute = self._call_with_mock_execute(
            self.config, ["example.org"], "/foo/bar")
        assert mock_execute.called is False
        assert mock_logger.info.call_count == 2

    def test_no_hooks(self):
        self.config.renew_hook = None
        os.remove(self.dir_hook)

        with mock.patch("certbot._internal.hooks.logger") as mock_logger:
            mock_execute = self._call_with_mock_execute(
                self.config, ["example.org"], "/foo/bar")
        assert mock_execute.called is False
        assert mock_logger.info.called is False

    def test_overlap(self):
        self.config.renew_hook = self.dir_hook
        mock_execute = self._call_with_mock_execute(
            self.config, ["example.net", "example.org"], "/foo/bar")
        mock_execute.assert_called_once_with("deploy-hook", self.dir_hook, env=mock.ANY)

    def test_no_overlap(self):
        mock_execute = self._call_with_mock_execute(
            self.config, ["example.org"], "/foo/bar")
        mock_execute.assert_any_call("deploy-hook", self.dir_hook, env=mock.ANY)
        mock_execute.assert_called_with("deploy-hook", self.config.renew_hook, env=mock.ANY)


class ListHooksTest(test_util.TempDirTestCase):
    """Tests for certbot._internal.hooks.list_hooks."""

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.hooks import list_hooks
        return list_hooks(*args, **kwargs)

    def test_empty(self):
        assert not self._call(self.tempdir)

    def test_multiple(self):
        names = sorted(
            os.path.join(self.tempdir, basename)
            for basename in ("foo", "bar", "baz", "qux")
        )
        for name in names:
            create_hook(name)

        assert self._call(self.tempdir) == names

    def test_single(self):
        name = os.path.join(self.tempdir, "foo")
        create_hook(name)

        assert self._call(self.tempdir) == [name]

    def test_ignore_tilde(self):
        name = os.path.join(self.tempdir, "foo~")
        create_hook(name)

        assert self._call(self.tempdir) == []


def create_hook(file_path):
    """Creates an executable file at the specified path.

    :param str file_path: path to create the file at

    """
    util.safe_open(file_path, mode="w", chmod=0o744).close()


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
