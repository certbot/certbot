"""Tests for certbot.plugins.dns_common."""

import argparse
import collections
import logging
import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock

from certbot import errors
from certbot import util
from certbot.compat import os
from certbot.display import util as display_util
from certbot.plugins import dns_common
from certbot.plugins import dns_test_common
from certbot.tests import util as test_util


class _FakeDNSAuthenticator(dns_common.DNSAuthenticator):
    _setup_credentials = mock.MagicMock()
    _perform = mock.MagicMock()
    _cleanup = mock.MagicMock()

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'A fake authenticator for testing.'


class DNSAuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    # pylint: disable=protected-access

    def setUp(self):
        super(DNSAuthenticatorTest, self).setUp()

        self.configure(_FakeDNSAuthenticator(self.config, "fake"),
                       {"config_key": 1, "other_key": None, "file_path": None})

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-d", "--domains",
                                 action="append", default=[])
        self.auth.inject_parser_options(self.parser, "fake")

    def test_perform(self):
        self.auth.perform([self.achall])

        self.auth._perform.assert_called_once_with(
            "_acme-challenge." + dns_test_common.DOMAIN,
            "_acme-challenge." + dns_test_common.DOMAIN,
            mock.ANY)

    def test_cleanup(self):
        self.auth._attempt_cleanup = True

        self.auth.cleanup([self.achall])

        self.auth._cleanup.assert_called_once_with(
            "_acme-challenge." + dns_test_common.DOMAIN,
            "_acme-challenge." + dns_test_common.DOMAIN,
            mock.ANY)

    def test_validation_domain_name(self):
        # Validation domain name without override

        vdn = self.auth.validation_domain_name(self.achall)

        self.assertEqual(vdn, self.achall.validation_domain_name(self.achall.domain))

    @test_util.patch_get_utility()
    def test_prompt(self, mock_get_utility):
        mock_display = mock_get_utility()
        mock_display.input.side_effect = ((display_util.OK, "",),
                                          (display_util.OK, "value",))

        self.auth._configure("other_key", "")
        self.assertEqual(self.auth.config.fake_other_key, "value")

    @test_util.patch_get_utility()
    def test_prompt_canceled(self, mock_get_utility):
        mock_display = mock_get_utility()
        mock_display.input.side_effect = ((display_util.CANCEL, "c",),)

        self.assertRaises(errors.PluginError, self.auth._configure, "other_key", "")

    @test_util.patch_get_utility()
    def test_prompt_file(self, mock_get_utility):
        path = os.path.join(self.tempdir, 'file.ini')
        open(path, "wb").close()

        mock_display = mock_get_utility()
        mock_display.directory_select.side_effect = ((display_util.OK, "",),
                                                     (display_util.OK, "not-a-file.ini",),
                                                     (display_util.OK, self.tempdir),
                                                     (display_util.OK, path,))

        self.auth._configure_file("file_path", "")
        self.assertEqual(self.auth.config.fake_file_path, path)

    @test_util.patch_get_utility()
    def test_prompt_file_canceled(self, mock_get_utility):
        mock_display = mock_get_utility()
        mock_display.directory_select.side_effect = ((display_util.CANCEL, "c",),)

        self.assertRaises(errors.PluginError, self.auth._configure_file, "file_path", "")

    def test_configure_credentials(self):
        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"fake_test": "value"}, path)
        setattr(self.config, "fake_credentials", path)

        credentials = self.auth._configure_credentials("credentials", "", {"test": ""})

        self.assertEqual(credentials.conf("test"), "value")

    @test_util.patch_get_utility()
    def test_prompt_credentials(self, mock_get_utility):
        bad_path = os.path.join(self.tempdir, 'bad-file.ini')
        dns_test_common.write({"fake_other": "other_value"}, bad_path)

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"fake_test": "value"}, path)
        setattr(self.config, "fake_credentials", "")

        mock_display = mock_get_utility()
        mock_display.directory_select.side_effect = ((display_util.OK, "",),
                                                     (display_util.OK, "not-a-file.ini",),
                                                     (display_util.OK, self.tempdir),
                                                     (display_util.OK, bad_path),
                                                     (display_util.OK, path,))

        credentials = self.auth._configure_credentials("credentials", "", {"test": ""})
        self.assertEqual(credentials.conf("test"), "value")


class ChallengeOverrideAuthenticatorTest(test_util.TempDirTestCase):

    def setUp(self):
        super(ChallengeOverrideAuthenticatorTest, self).setUp()

        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-d", "--domains",
                                 action="append", default=[])
        _FakeDNSAuthenticator.inject_parser_options(self.parser, "fake")

    def parse_args(self, *args):  # pylint: disable=missing-docstring
        # pylint: disable=attribute-defined-outside-init
        self.auth = _FakeDNSAuthenticator(self.parser.parse_args(args), "fake")

    def vdn(self, domain):  # pylint: disable=missing-docstring
        return self.auth.validation_domain_name(dns_test_common.dns_challenge(domain))

    def test_no_override(self):
        dom = "no-override.com"
        self.parse_args("-d", dom)

        # Check that override map is present and empty

        self.assertEqual(self.auth.conf("validation-domain-map"), {})

        # Check that challenge override is set to the default name

        self.assertEqual(self.auth.conf("validation-domain"), "{acme}")

        # Check that the computed validation domain name is the default name

        self.assertEqual(self.vdn(dom), "_acme-challenge." + dom)

    def test_validation_domain(self):
        self.parse_args(
            "-d", "d0.com",
            "--fake-validation-domain", "c1.com",
            "-d", "d1.com",
            "--fake-validation-domain", "c2.com",
            "-d", "d2.com")

        # Check contents of override map

        self.assertEqual(self.auth.conf("validation-domain-map"),
                         {"d0.com": "{acme}",
                          "d1.com": "c1.com"})

        # Check last value of challenge override

        self.assertEqual(self.auth.conf("validation-domain"), "c2.com")

        # Domain before first override gets default challenge

        self.assertEqual(self.vdn("d0.com"), "_acme-challenge.d0.com")

        # Domain after first override and before second gets first override

        self.assertEqual(self.vdn("d1.com"), "c1.com")

        # Domain after second (and last) override gets second override

        self.assertEqual(self.vdn("d2.com"), "c2.com")


class CredentialsConfigurationTest(test_util.TempDirTestCase):
    class _MockLoggingHandler(logging.Handler):
        messages = None

        def __init__(self, *args, **kwargs):
            self.reset()
            logging.Handler.__init__(self, *args, **kwargs)

        def emit(self, record):
            self.messages[record.levelname.lower()].append(record.getMessage())

        def reset(self):
            """Allows the handler to be reset between tests."""
            self.messages = collections.defaultdict(list)

    def test_valid_file(self):
        path = os.path.join(self.tempdir, 'too-permissive-file.ini')

        dns_test_common.write({"test": "value", "other": 1}, path)

        credentials_configuration = dns_common.CredentialsConfiguration(path)
        self.assertEqual("value", credentials_configuration.conf("test"))
        self.assertEqual("1", credentials_configuration.conf("other"))

    def test_nonexistent_file(self):
        path = os.path.join(self.tempdir, 'not-a-file.ini')

        self.assertRaises(errors.PluginError, dns_common.CredentialsConfiguration, path)

    def test_valid_file_with_unsafe_permissions(self):
        log = self._MockLoggingHandler()
        dns_common.logger.addHandler(log)

        path = os.path.join(self.tempdir, 'too-permissive-file.ini')
        util.safe_open(path, "wb", 0o744).close()

        dns_common.CredentialsConfiguration(path)

        self.assertEqual(1, len([_ for _ in log.messages['warning'] if _.startswith("Unsafe")]))


class CredentialsConfigurationRequireTest(test_util.TempDirTestCase):

    def setUp(self):
        super(CredentialsConfigurationRequireTest, self).setUp()

        self.path = os.path.join(self.tempdir, 'file.ini')

    def _write(self, values):
        dns_test_common.write(values, self.path)

    def test_valid(self):
        self._write({"test": "value", "other": 1})

        credentials_configuration = dns_common.CredentialsConfiguration(self.path)
        credentials_configuration.require({"test": "", "other": ""})

    def test_valid_but_extra(self):
        self._write({"test": "value", "other": 1})

        credentials_configuration = dns_common.CredentialsConfiguration(self.path)
        credentials_configuration.require({"test": ""})

    def test_valid_empty(self):
        self._write({})

        credentials_configuration = dns_common.CredentialsConfiguration(self.path)
        credentials_configuration.require({})

    def test_missing(self):
        self._write({})

        credentials_configuration = dns_common.CredentialsConfiguration(self.path)
        self.assertRaises(errors.PluginError, credentials_configuration.require, {"test": ""})

    def test_blank(self):
        self._write({"test": ""})

        credentials_configuration = dns_common.CredentialsConfiguration(self.path)
        self.assertRaises(errors.PluginError, credentials_configuration.require, {"test": ""})

    def test_typo(self):
        self._write({"tets": "typo!"})

        credentials_configuration = dns_common.CredentialsConfiguration(self.path)
        self.assertRaises(errors.PluginError, credentials_configuration.require, {"test": ""})


class DomainNameGuessTest(unittest.TestCase):

    def test_simple_case(self):
        self.assertTrue(
            'example.com' in
            dns_common.base_domain_name_guesses("example.com")
        )

    def test_sub_domain(self):
        self.assertTrue(
            'example.com' in
            dns_common.base_domain_name_guesses("foo.bar.baz.example.com")
        )

    def test_second_level_domain(self):
        self.assertTrue(
            'example.co.uk' in
            dns_common.base_domain_name_guesses("foo.bar.baz.example.co.uk")
        )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
