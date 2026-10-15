"""Tests for certbot._internal.plugins.dns_persist"""
from textwrap import dedent
import sys
import pytest
import os
from unittest import mock

from acme import challenges
from certbot import errors
from certbot.compat import filesystem
from certbot.tests import acme_util
from certbot.tests import util as test_util


class AuthenticatorTest(test_util.TempDirTestCase):
    def setUp(self):
        super().setUp()
        get_display_patch = test_util.patch_display_util()
        self.mock_get_display = get_display_patch.start()
        for d in ["config_dir", "work_dir", "in_progress"]:
            filesystem.mkdir(os.path.join(self.tempdir, d))
        self.achalls = [
            acme_util.DNS_PERSIST_01_A,
            acme_util.DNS_PERSIST_01_A_WILDCARD,
        ]
        # "backup_dir" and "temp_checkpoint_dir" get created in
        # certbot.util.make_or_verify_dir() during the Reverter
        # initialization.
        self.config = mock.MagicMock(
            dns_persist_setup=False, dns_persist_setup_hook=None,
            dns_persist_setup_cleanup_hook=None,
            noninteractive_mode=False, validate_hooks=False,
            config_dir=os.path.join(self.tempdir, "config_dir"),
            work_dir=os.path.join(self.tempdir, "work_dir"),
            backup_dir=os.path.join(self.tempdir, "backup_dir"),
            temp_checkpoint_dir=os.path.join(
                                        self.tempdir, "temp_checkpoint_dir"),
            in_progress_dir=os.path.join(self.tempdir, "in_progess"))

        from certbot._internal.plugins.dns_persist import Authenticator
        self.auth = Authenticator(self.config, name='dns-persist')

    def test_setup_manual(self):
        self.config.dns_persist_setup = True
        res = self.auth.perform(self.achalls)
        assert res == [achall.response() for achall in self.achalls]
        assert self.mock_get_display().notification.call_count == len(self.achalls)
        for i, (args, kwargs) in enumerate(self.mock_get_display().notification.call_args_list):
            achall = self.achalls[i]
            (domain, validation) = achall.get_dns_txt_record()
            assert domain in args[0]
            assert validation in args[0]
            assert kwargs['wrap'] is False

    def _echo_env_hook(self, out_path: str, env_vars: list[str]) -> str:
        print_lines = [f"print(os.environ.get('{var}'));" for var in env_vars]
        return dedent(f"""\
            {sys.executable} -c "
            from certbot.compat import os;
            {' '.join(print_lines)}
            " >> {out_path}
            """)

    def test_setup_with_hook(self):
        tmp_path = os.path.join(self.tempdir, 'out')
        self.config.dns_persist_setup = True
        self.config.dns_persist_setup_hook = self._echo_env_hook(tmp_path, [
            'CERTBOT_DOMAIN',
            'CERTBOT_VALIDATION',
        ])
        res = self.auth.perform(self.achalls)
        assert res == [achall.response() for achall in self.achalls]
        expected_out = []
        for achall in self.achalls:
            (domain, validation) = achall.get_dns_txt_record()
            expected_out.append(domain)
            expected_out.append(validation)
        with open(tmp_path) as f:
            out = [line.strip() for line in f.readlines()]
            assert out == expected_out

    def test_cleanup_hook(self):
        tmp_path = os.path.join(self.tempdir, 'out')
        self.config.dns_persist_setup = True
        self.config.dns_persist_setup_cleanup_hook = self._echo_env_hook(tmp_path, [])
        self.auth.cleanup(self.achalls)
        assert os.path.isfile(tmp_path)

    def test_hook_with_no_setup(self):
        self.config.dns_persist_setup_hook = '/bin/true'
        with pytest.raises(errors.PluginError):
            self.auth.prepare()
        self.config.dns_persist_setup = True
        self.auth.prepare()

    def test_cleanup_hook_with_no_setup(self):
        self.config.dns_persist_setup_cleanup_hook = '/bin/true'
        with pytest.raises(errors.PluginError):
            self.auth.prepare()
        self.config.dns_persist_setup = True
        self.auth.prepare()

    def test_more_info(self):
        assert isinstance(self.auth.more_info(), str)

    def test_get_chall_pref(self):
        assert self.auth.get_chall_pref('example.org') == [challenges.DNSPersist01]


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
