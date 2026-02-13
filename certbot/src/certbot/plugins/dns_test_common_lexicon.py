"""Base test class for DNS authenticators built on Lexicon."""
import contextlib
import sys
from types import ModuleType
from typing import Any
from typing import cast
from typing import Generator
from typing import Protocol
from unittest import mock
from unittest.mock import MagicMock
import warnings

import josepy as jose
from requests import Response
from requests.exceptions import HTTPError
from requests.exceptions import RequestException

from certbot import errors
from certbot.achallenges import AnnotatedChallenge
from certbot.plugins import dns_test_common

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    from certbot.plugins.dns_common_lexicon import LexiconClient

from certbot.plugins.dns_test_common import _AuthenticatorCallableTestCase
from certbot.tests import util as test_util

DOMAIN = 'example.com'
KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))

DOMAIN_NOT_FOUND = Exception('No domain found')
GENERIC_ERROR = RequestException
LOGIN_ERROR = HTTPError('400 Client Error: ...', response=Response())
UNKNOWN_LOGIN_ERROR = HTTPError('500 Surprise! Error: ...', response=Response())


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

class BaseLexiconAuthenticatorTest(dns_test_common.BaseAuthenticatorTest):  # pragma: no cover

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


class BaseLexiconClientTest:  # pragma: no cover
    DOMAIN_NOT_FOUND = DOMAIN_NOT_FOUND
    GENERIC_ERROR = GENERIC_ERROR
    LOGIN_ERROR = LOGIN_ERROR
    UNKNOWN_LOGIN_ERROR = UNKNOWN_LOGIN_ERROR

    record_prefix = "_acme-challenge"
    record_name = record_prefix + "." + DOMAIN
    record_content = "bar"

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
def _patch_lexicon_client() -> Generator[tuple[MagicMock, MagicMock], None, None]:
    with mock.patch('certbot.plugins.dns_common_lexicon.Client') as mock_client:
        mock_operations = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_operations
        yield mock_client, mock_operations


# This class takes a similar approach to the cryptography project to deprecate attributes
# in public modules. See the _ModuleWithDeprecation class here:
# https://github.com/pyca/cryptography/blob/91105952739442a74582d3e62b3d2111365b0dc7/src/cryptography/utils.py#L129
class _DeprecationModule:
    """
    Internal class delegating to a module, and displaying warnings when attributes
    related to deprecated attributes in the current module.
    """
    def __init__(self, module: ModuleType):
        self.__dict__['_module'] = module

    def __getattr__(self, attr: str) -> Any:
        if attr in ('BaseLexiconAuthenticatorTest', 'BaseLexiconClientTest'):
            warnings.warn(f'{attr} attribute in {__name__} module is deprecated '
                          'and will be removed soon.',
                          DeprecationWarning, stacklevel=2)
        return getattr(self._module, attr)

    def __setattr__(self, attr: str, value: Any) -> None:  # pragma: no cover
        setattr(self._module, attr, value)

    def __delattr__(self, attr: str) -> Any:  # pragma: no cover
        delattr(self._module, attr)

    def __dir__(self) -> list[str]:  # pragma: no cover
        return ['_module'] + dir(self._module)


# Patching ourselves to warn about deprecation and planned removal of some elements in the module.
sys.modules[__name__] = cast(ModuleType, _DeprecationModule(sys.modules[__name__]))
