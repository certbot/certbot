"""Tests for letsencrypt.plugins.webroot."""
import os
import shutil
import tempfile
import unittest
import stat

import mock

from acme import challenges
from acme import jose

from letsencrypt import achallenges
from letsencrypt import errors

from letsencrypt.tests import acme_util
from letsencrypt.tests import test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class AuthenticatorTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.webroot.Authenticator."""

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.HTTP01_P, domain="thing.com", account_key=KEY)

    def setUp(self):
        from letsencrypt.plugins.webroot import Authenticator
        self.path = tempfile.mkdtemp()
        self.validation_path = os.path.join(
            self.path, ".well-known", "acme-challenge",
            "ZXZhR3hmQURzNnBTUmIyTEF2OUlaZjE3RHQzanV4R0orUEN0OTJ3citvQQ")
        self.config = mock.MagicMock(webroot_path=self.path,
                                     webroot_map={"thing.com": self.path})
        self.auth = Authenticator(self.config, "webroot")
        self.auth.prepare()

    def tearDown(self):
        shutil.rmtree(self.path)

    def test_more_info(self):
        more_info = self.auth.more_info()
        self.assertTrue(isinstance(more_info, str))
        self.assertTrue(self.path in more_info)

    def test_add_parser_arguments(self):
        add = mock.MagicMock()
        self.auth.add_parser_arguments(add)
        self.assertEqual(0, add.call_count) # became 0 when we moved the args to cli.py!

    def test_prepare_bad_root(self):
        self.config.webroot_path = os.path.join(self.path, "null")
        self.config.webroot_map["thing.com"] = self.config.webroot_path
        self.assertRaises(errors.PluginError, self.auth.prepare)

    def test_prepare_missing_root(self):
        self.config.webroot_path = None
        self.config.webroot_map = {}
        self.assertRaises(errors.PluginError, self.auth.prepare)

    def test_prepare_full_root_exists(self):
        # prepare() has already been called once in setUp()
        self.auth.prepare()  # shouldn't raise any exceptions

    def test_prepare_reraises_other_errors(self):
        self.auth.full_path = os.path.join(self.path, "null")
        os.chmod(self.path, 0o000)
        self.assertRaises(errors.PluginError, self.auth.prepare)
        os.chmod(self.path, 0o700)

    def test_prepare_permissions(self):

        # Remove exec bit from permission check, so that it
        # matches the file
        self.auth.perform([self.achall])
        parent_permissions = (stat.S_IMODE(os.stat(self.path).st_mode) &
                              ~stat.S_IEXEC)

        actual_permissions = stat.S_IMODE(os.stat(self.validation_path).st_mode)

        self.assertEqual(parent_permissions, actual_permissions)
        parent_gid = os.stat(self.path).st_gid
        parent_uid = os.stat(self.path).st_uid

        self.assertEqual(os.stat(self.validation_path).st_gid, parent_gid)
        self.assertEqual(os.stat(self.validation_path).st_uid, parent_uid)

    def test_perform_cleanup(self):
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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
