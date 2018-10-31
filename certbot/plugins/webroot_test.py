"""Tests for certbot.plugins.webroot."""

from __future__ import print_function

import argparse
import errno
import json
import os
import shutil
import tempfile
import unittest

import josepy as jose
import mock
import six

from acme import challenges

from certbot import achallenges
from certbot import compat
from certbot import errors
from certbot.display import util as display_util

from certbot.tests import acme_util
from certbot.tests import util as test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    """Tests for certbot.plugins.webroot.Authenticator."""

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.HTTP01_P, domain="thing.com", account_key=KEY)

    def setUp(self):
        from certbot.plugins.webroot import Authenticator
        self.path = tempfile.mkdtemp()
        self.partial_root_challenge_path = os.path.join(
            self.path, ".well-known")
        self.root_challenge_path = os.path.join(
            self.path, ".well-known", "acme-challenge")
        self.validation_path = os.path.join(
            self.root_challenge_path,
            "ZXZhR3hmQURzNnBTUmIyTEF2OUlaZjE3RHQzanV4R0orUEN0OTJ3citvQQ")
        self.config = mock.MagicMock(webroot_path=self.path,
                                     webroot_map={"thing.com": self.path})
        self.auth = Authenticator(self.config, "webroot")

    def tearDown(self):
        shutil.rmtree(self.path)

    def test_more_info(self):
        more_info = self.auth.more_info()
        self.assertTrue(isinstance(more_info, six.string_types))
        self.assertTrue(self.path in more_info)

    def test_add_parser_arguments(self):
        add = mock.MagicMock()
        self.auth.add_parser_arguments(add)
        self.assertEqual(2, add.call_count)

    def test_prepare(self):
        self.auth.prepare()  # shouldn't raise any exceptions

    @test_util.patch_get_utility()
    def test_webroot_from_list(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {"otherthing.com": self.path}
        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 1,)

        self.auth.perform([self.achall])
        self.assertTrue(mock_display.menu.called)
        for call in mock_display.menu.call_args_list:
            self.assertTrue(self.achall.domain in call[0][0])
            self.assertTrue(all(
                webroot in call[0][1]
                for webroot in six.itervalues(self.config.webroot_map)))
        self.assertEqual(self.config.webroot_map[self.achall.domain],
                         self.path)

    @test_util.patch_get_utility()
    def test_webroot_from_list_help_and_cancel(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {"otherthing.com": self.path}

        mock_display = mock_get_utility()
        mock_display.menu.side_effect = ((display_util.CANCEL, -1),)
        self.assertRaises(errors.PluginError, self.auth.perform, [self.achall])
        self.assertTrue(mock_display.menu.called)
        for call in mock_display.menu.call_args_list:
            self.assertTrue(self.achall.domain in call[0][0])
            self.assertTrue(all(
                webroot in call[0][1]
                for webroot in six.itervalues(self.config.webroot_map)))

    @test_util.patch_get_utility()
    def test_new_webroot(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {"something.com": self.path}

        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 0,)
        with mock.patch('certbot.display.ops.validated_directory') as m:
            m.side_effect = ((display_util.CANCEL, -1),
                             (display_util.OK, self.path,))

            self.auth.perform([self.achall])

        self.assertEqual(self.config.webroot_map[self.achall.domain], self.path)

    @test_util.patch_get_utility()
    def test_new_webroot_empty_map_cancel(self, mock_get_utility):
        self.config.webroot_path = []
        self.config.webroot_map = {}

        mock_display = mock_get_utility()
        mock_display.menu.return_value = (display_util.OK, 0,)
        with mock.patch('certbot.display.ops.validated_directory') as m:
            m.return_value = (display_util.CANCEL, -1)
            self.assertRaises(errors.PluginError,
                              self.auth.perform,
                              [self.achall])

    def test_perform_missing_root(self):
        self.config.webroot_path = None
        self.config.webroot_map = {}
        self.assertRaises(errors.PluginError, self.auth.perform, [])

    def test_perform_reraises_other_errors(self):
        self.auth.full_path = os.path.join(self.path, "null")
        permission_canary = os.path.join(self.path, "rnd")
        with open(permission_canary, "w") as f:
            f.write("thingimy")
        os.chmod(self.path, 0o000)
        try:
            open(permission_canary, "r")
            print("Warning, running tests as root skips permissions tests...")
        except IOError:
            # ok, permissions work, test away...
            self.assertRaises(errors.PluginError, self.auth.perform, [])
        os.chmod(self.path, 0o700)

    @test_util.skip_on_windows('On Windows, there is no chown.')
    @mock.patch("certbot.plugins.webroot.os.chown")
    def test_failed_chown(self, mock_chown):
        mock_chown.side_effect = OSError(errno.EACCES, "msg")
        self.auth.perform([self.achall])  # exception caught and logged


    @test_util.patch_get_utility()
    def test_perform_new_webroot_not_in_map(self, mock_get_utility):
        new_webroot = tempfile.mkdtemp()
        self.config.webroot_path = []
        self.config.webroot_map = {"whatever.com": self.path}
        mock_display = mock_get_utility()
        mock_display.menu.side_effect = ((display_util.OK, 0),
                                         (display_util.OK, new_webroot))
        achall = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.HTTP01_P, domain="something.com", account_key=KEY)
        with mock.patch('certbot.display.ops.validated_directory') as m:
            m.return_value = (display_util.OK, new_webroot,)
            self.auth.perform([achall])
        self.assertEqual(self.config.webroot_map[achall.domain], new_webroot)

    def test_perform_permissions(self):
        self.auth.prepare()

        # Remove exec bit from permission check, so that it
        # matches the file
        self.auth.perform([self.achall])
        self.assertTrue(compat.compare_file_modes(os.stat(self.validation_path).st_mode, 0o644))

        # Check permissions of the directories

        for dirpath, dirnames, _ in os.walk(self.path):
            for directory in dirnames:
                full_path = os.path.join(dirpath, directory)
                self.assertTrue(compat.compare_file_modes(os.stat(full_path).st_mode, 0o755))

        parent_gid = os.stat(self.path).st_gid
        parent_uid = os.stat(self.path).st_uid

        self.assertEqual(os.stat(self.validation_path).st_gid, parent_gid)
        self.assertEqual(os.stat(self.validation_path).st_uid, parent_uid)

    def test_perform_cleanup(self):
        self.auth.prepare()
        responses = self.auth.perform([self.achall])
        self.assertEqual(1, len(responses))
        self.assertTrue(os.path.exists(self.validation_path))
        with open(self.validation_path) as validation_f:
            validation = validation_f.read()
        self.assertTrue(
            challenges.KeyAuthorizationChallengeResponse(
                key_authorization=validation).verify(
                    self.achall.chall, KEY.public_key()))

        self.auth.cleanup([self.achall])
        self.assertFalse(os.path.exists(self.validation_path))
        self.assertFalse(os.path.exists(self.root_challenge_path))
        self.assertFalse(os.path.exists(self.partial_root_challenge_path))

    def test_perform_cleanup_existing_dirs(self):
        os.mkdir(self.partial_root_challenge_path)
        self.auth.prepare()
        self.auth.perform([self.achall])
        self.auth.cleanup([self.achall])

        # Ensure we don't "clean up" directories that previously existed
        self.assertFalse(os.path.exists(self.validation_path))
        self.assertFalse(os.path.exists(self.root_challenge_path))

    def test_perform_cleanup_multiple_challenges(self):
        bingo_achall = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=acme_util.chall_to_challb(
                challenges.HTTP01(token=b"bingo"), "pending"),
            domain="thing.com", account_key=KEY)

        bingo_validation_path = "YmluZ28"
        os.mkdir(self.partial_root_challenge_path)
        self.auth.prepare()
        self.auth.perform([bingo_achall, self.achall])

        self.auth.cleanup([self.achall])
        self.assertFalse(os.path.exists(bingo_validation_path))
        self.assertTrue(os.path.exists(self.root_challenge_path))
        self.auth.cleanup([bingo_achall])
        self.assertFalse(os.path.exists(self.validation_path))
        self.assertFalse(os.path.exists(self.root_challenge_path))

    def test_cleanup_leftovers(self):
        self.auth.prepare()
        self.auth.perform([self.achall])

        leftover_path = os.path.join(self.root_challenge_path, 'leftover')
        os.mkdir(leftover_path)

        self.auth.cleanup([self.achall])
        self.assertFalse(os.path.exists(self.validation_path))
        self.assertTrue(os.path.exists(self.root_challenge_path))

        os.rmdir(leftover_path)

    @mock.patch('os.rmdir')
    def test_cleanup_failure(self, mock_rmdir):
        self.auth.prepare()
        self.auth.perform([self.achall])

        os_error = OSError()
        os_error.errno = errno.EACCES
        mock_rmdir.side_effect = os_error

        self.auth.cleanup([self.achall])
        self.assertFalse(os.path.exists(self.validation_path))
        self.assertTrue(os.path.exists(self.root_challenge_path))


class WebrootActionTest(unittest.TestCase):
    """Tests for webroot argparse actions."""

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.HTTP01_P, domain="thing.com", account_key=KEY)

    def setUp(self):
        from certbot.plugins.webroot import Authenticator
        self.path = tempfile.mkdtemp()
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-d", "--domains",
                                 action="append", default=[])
        Authenticator.inject_parser_options(self.parser, "webroot")

    def test_webroot_map_action(self):
        args = self.parser.parse_args(
            ["--webroot-map", json.dumps({'thing.com': self.path})])
        self.assertEqual(args.webroot_map["thing.com"], self.path)

    def test_domain_before_webroot(self):
        args = self.parser.parse_args(
            "-d {0} -w {1}".format(self.achall.domain, self.path).split())
        config = self._get_config_after_perform(args)
        self.assertEqual(config.webroot_map[self.achall.domain], self.path)

    def test_domain_before_webroot_error(self):
        self.assertRaises(errors.PluginError, self.parser.parse_args,
                          "-d foo -w bar -w baz".split())
        self.assertRaises(errors.PluginError, self.parser.parse_args,
                          "-d foo -w bar -d baz -w qux".split())

    def test_multiwebroot(self):
        args = self.parser.parse_args("-w {0} -d {1} -w {2} -d bar".format(
            self.path, self.achall.domain, tempfile.mkdtemp()).split())
        self.assertEqual(args.webroot_map[self.achall.domain], self.path)
        config = self._get_config_after_perform(args)
        self.assertEqual(
            config.webroot_map[self.achall.domain], self.path)

    def _get_config_after_perform(self, config):
        from certbot.plugins.webroot import Authenticator
        auth = Authenticator(config, "webroot")
        auth.perform([self.achall])
        return auth.config


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
