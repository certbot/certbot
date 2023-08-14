"""Base test class for DNS authenticators built on Lexicon."""
import contextlib
from typing import Any, Tuple, Generator
from typing import TYPE_CHECKING
from unittest import mock
from unittest.mock import MagicMock
import warnings

import josepy as jose
from requests.exceptions import HTTPError
from requests.exceptions import RequestException

from certbot import errors
from certbot.achallenges import AnnotatedChallenge
from certbot.plugins import dns_test_common
from certbot.plugins.dns_common_lexicon import LexiconClient
from certbot.plugins.dns_test_common import _AuthenticatorCallableTestCase
from certbot.tests import util as test_util

if TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import Protocol
else:
    Protocol = object

DOMAIN = 'example.com'
KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))

DOMAIN_NOT_FOUND = Exception('No domain found')
GENERIC_ERROR = RequestException
LOGIN_ERROR = HTTPError('400 Client Error: ...')
UNKNOWN_LOGIN_ERROR = HTTPError('500 Surprise! Error: ...')


class _AuthenticatorCallableLexiconTestCase(_AuthenticatorCallableTestCase, Protocol):
    """
    Protocol describing a TestCase suitable to test challenges against
    a mocked LexiconClient instance.
    """
    mock_client: MagicMock
    achall: AnnotatedChallenge


class _LexiconAwareTestCase(Protocol):
    """
    Protocol describing a TestCase suitable to test a real LexiconClient instance.
    """
    client: LexiconClient
    provider_mock: MagicMock

    record_prefix: str
    record_name: str
    record_content: str

    DOMAIN_NOT_FOUND: Exception
    GENERIC_ERROR: Exception
    LOGIN_ERROR: Exception
    UNKNOWN_LOGIN_ERROR: Exception

    def assertRaises(self, *unused_args: Any) -> None:
        """
        See
        https://docs.python.org/3/library/unittest.html#unittest.TestCase.assertRaises
        """


# These classes are intended to be subclassed/mixed in, so not all members are defined.
# pylint: disable=no-member

class BaseLexiconAuthenticatorTest(dns_test_common.BaseAuthenticatorTest):

    def __init_subclass__(cls, **kwargs: Any) -> None:  # pragma: no cover
        super().__init_subclass__(**kwargs)
        warnings.warn("BaseLexiconAuthenticatorTest class is deprecated and will be "
                      "removed in the next Certbot major release. Please use "
                      "LexiconDNSAuthenticator instead.",
                      DeprecationWarning)

    @test_util.patch_display_util()
    def test_perform(self: _AuthenticatorCallableLexiconTestCase,
                     unused_mock_get_utility: Any) -> None:
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self: _AuthenticatorCallableLexiconTestCase) -> None:
        self.auth._attempt_cleanup = True  # _attempt_cleanup | pylint: disable=protected-access
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.'+DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class BaseLexiconClientTest:
    DOMAIN_NOT_FOUND = DOMAIN_NOT_FOUND
    GENERIC_ERROR = GENERIC_ERROR
    LOGIN_ERROR = LOGIN_ERROR
    UNKNOWN_LOGIN_ERROR = UNKNOWN_LOGIN_ERROR

    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"

    def __init_subclass__(cls, **kwargs: Any) -> None:  # pragma: no cover
        super().__init_subclass__(**kwargs)
        warnings.warn("BaseLexiconClientTest class is deprecated and will be removed in "
                      "the next Certbot major release. Please use LexiconDNSAuthenticator instead.",
                      DeprecationWarning)

    def test_add_txt_record(self: _LexiconAwareTestCase) -> None:
        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(rtype='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_try_twice_to_find_domain(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND, '']

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.create_record.assert_called_with(rtype='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_add_txt_record_fail_to_find_domain(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,]

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_fail_to_authenticate(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = self.LOGIN_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_fail_to_authenticate_with_unknown_error(
            self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = self.UNKNOWN_LOGIN_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_finding_domain(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = self.GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_add_txt_record_error_adding_record(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.create_record.side_effect = self.GENERIC_ERROR

        self.assertRaises(errors.PluginError,
                          self.client.add_txt_record,
                          DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record(self: _LexiconAwareTestCase) -> None:
        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

        self.provider_mock.delete_record.assert_called_with(rtype='TXT',
                                                            name=self.record_name,
                                                            content=self.record_content)

    def test_del_txt_record_fail_to_find_domain(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = [self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND,
                                                       self.DOMAIN_NOT_FOUND, ]

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_fail_to_authenticate(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = self.LOGIN_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_fail_to_authenticate_with_unknown_error(
            self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = self.UNKNOWN_LOGIN_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_finding_domain(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.authenticate.side_effect = self.GENERIC_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)

    def test_del_txt_record_error_deleting_record(self: _LexiconAwareTestCase) -> None:
        self.provider_mock.delete_record.side_effect = self.GENERIC_ERROR

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content)


class _BaseLexiconDNSAuthenticatorTestProto(_AuthenticatorCallableTestCase, Protocol):
    """Protocol for BaseLexiconDNSAuthenticatorTest instances"""
    DOMAIN_NOT_FOUND: Exception
    GENERIC_ERROR: Exception
    LOGIN_ERROR: Exception
    UNKNOWN_LOGIN_ERROR: Exception

    achall: AnnotatedChallenge


class BaseLexiconDNSAuthenticatorTest(dns_test_common.BaseAuthenticatorTest):

    DOMAIN_NOT_FOUND = DOMAIN_NOT_FOUND
    GENERIC_ERROR = GENERIC_ERROR
    LOGIN_ERROR = LOGIN_ERROR
    UNKNOWN_LOGIN_ERROR = UNKNOWN_LOGIN_ERROR

    def test_perform_succeed(self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with test_util.patch_display_util():
            with _patch_lexicon_client() as (mock_client, mock_operations):
                self.auth.perform([self.achall])

        mock_client.assert_called()
        config = mock_client.call_args[0][0]
        self.assertEqual(DOMAIN, config.resolve('lexicon:domain'))

        mock_operations.create_record.assert_called_with(
            rtype='TXT', name=f'_acme-challenge.{DOMAIN}', content=mock.ANY)

    def test_perform_with_one_domain_resolution_failure_succeed(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with test_util.patch_display_util():
            with _patch_lexicon_client() as (mock_client, mock_operations):
                mock_client.return_value.__enter__.side_effect = [
                    self.DOMAIN_NOT_FOUND,  # First resolution domain attempt
                    mock_operations,  # Second resolution domain attempt
                    mock_operations,  # Create record operation
                ]
                self.auth.perform([self.achall])

    def test_perform_with_two_domain_resolution_failures_raise(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with test_util.patch_display_util():
            with _patch_lexicon_client() as (mock_client, _):
                mock_client.return_value.__enter__.side_effect = self.DOMAIN_NOT_FOUND
                self.assertRaises(errors.PluginError,
                                  self.auth.perform,
                                  [self.achall])

    def test_perform_with_domain_resolution_general_failure_raise(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with test_util.patch_display_util():
            with _patch_lexicon_client() as (mock_client, _):
                mock_client.return_value.__enter__.side_effect = self.GENERIC_ERROR
                self.assertRaises(errors.PluginError,
                                  self.auth.perform,
                                  [self.achall])

    def test_perform_with_auth_failure_raise(self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with test_util.patch_display_util():
            with _patch_lexicon_client() as (mock_client, _):
                mock_client.side_effect = self.LOGIN_ERROR
                self.assertRaises(errors.PluginError,
                                  self.auth.perform,
                                  [self.achall])

    def test_perform_with_unknown_auth_failure_raise(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with test_util.patch_display_util():
            with _patch_lexicon_client() as (mock_client, _):
                mock_client.side_effect = self.UNKNOWN_LOGIN_ERROR
                self.assertRaises(errors.PluginError,
                                  self.auth.perform,
                                  [self.achall])

    def test_perform_with_create_record_failure_raise(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with test_util.patch_display_util():
            with _patch_lexicon_client() as (_, mock_operations):
                mock_operations.create_record.side_effect = self.GENERIC_ERROR
                self.assertRaises(errors.PluginError,
                                  self.auth.perform,
                                  [self.achall])

    def test_cleanup_success(self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        self.auth._attempt_cleanup = True  # _attempt_cleanup | pylint: disable=protected-access
        with _patch_lexicon_client() as (mock_client, mock_operations):
            self.auth.cleanup([self.achall])

        mock_client.assert_called()
        config = mock_client.call_args[0][0]
        self.assertEqual(DOMAIN, config.resolve('lexicon:domain'))

        mock_operations.delete_record.assert_called_with(
            rtype='TXT', name=f'_acme-challenge.{DOMAIN}', content=mock.ANY)

    def test_cleanup_with_auth_failure_ignore(self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with _patch_lexicon_client() as (mock_client, _):
            mock_client.side_effect = self.LOGIN_ERROR
            self.auth.cleanup([self.achall])

    def test_cleanup_with_unknown_auth_failure_ignore(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with _patch_lexicon_client() as (mock_client, _):
            mock_client.side_effect = self.LOGIN_ERROR
            self.auth.cleanup([self.achall])

    def test_cleanup_with_domain_resolution_failure_ignore(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with _patch_lexicon_client() as (mock_client, _):
            mock_client.return_value.__enter__.side_effect = self.DOMAIN_NOT_FOUND
            self.auth.cleanup([self.achall])

    def test_cleanup_with_domain_resolution_general_failure_ignore(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with _patch_lexicon_client() as (mock_client, _):
            mock_client.return_value.__enter__.side_effect = self.GENERIC_ERROR
            self.auth.cleanup([self.achall])

    def test_cleanup_with_delete_record_failure_ignore(
            self: _BaseLexiconDNSAuthenticatorTestProto) -> None:
        with _patch_lexicon_client() as (_, mock_operations):
            mock_operations.create_record.side_effect = self.GENERIC_ERROR
            self.auth.cleanup([self.achall])


@contextlib.contextmanager
def _patch_lexicon_client() -> Generator[Tuple[MagicMock, MagicMock], None, None]:
    with mock.patch('certbot.plugins.dns_common_lexicon.Client') as mock_client:
        mock_operations = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_operations
        yield mock_client, mock_operations
