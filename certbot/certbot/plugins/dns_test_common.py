"""Base test class for DNS authenticators."""
import typing

import configobj
import josepy as jose

from acme import challenges
from certbot import achallenges
from certbot.compat import filesystem
from certbot.plugins.dns_common import DNSAuthenticator
from certbot.tests import acme_util
from certbot.tests import util as test_util

if typing.TYPE_CHECKING:
    from typing_extensions import Protocol
else:
    Protocol = object  # type: ignore



try:
    import mock
except ImportError:  # pragma: no cover
    from unittest import mock  # type: ignore


DOMAIN = 'example.com'
KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class _AuthenticatorCallableTestCase(Protocol):
    """Protocol describing a TestCase able to call a real DNSAuthenticator instance."""
    auth: DNSAuthenticator

    def assertTrue(self, *unused_args) -> None:
        """
        See
        https://docs.python.org/3/library/unittest.html#unittest.TestCase.assertTrue
        """
        ...

    def assertEqual(self, *unused_args) -> None:
        """
        See
        https://docs.python.org/3/library/unittest.html#unittest.TestCase.assertEqual
        """
        ...


class BaseAuthenticatorTest:
    """
    A base test class to reduce duplication between test code for DNS Authenticator Plugins.

    Assumes:
     * That subclasses also subclass unittest.TestCase
     * That the authenticator is stored as self.auth
    """

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01, domain=DOMAIN, account_key=KEY)

    def test_more_info(self: _AuthenticatorCallableTestCase):
        self.assertTrue(isinstance(self.auth.more_info(), str))  # pylint: disable=no-member

    def test_get_chall_pref(self: _AuthenticatorCallableTestCase):
        self.assertEqual(self.auth.get_chall_pref(None), [challenges.DNS01])  # pylint: disable=no-member

    def test_parser_arguments(self: _AuthenticatorCallableTestCase):
        m = mock.MagicMock()
        self.auth.add_parser_arguments(m)  # pylint: disable=no-member

        m.assert_any_call('propagation-seconds', type=int, default=mock.ANY, help=mock.ANY)


def write(values, path):
    """Write the specified values to a config file.

    :param dict values: A map of values to write.
    :param str path: Where to write the values.
    """

    config = configobj.ConfigObj()

    for key in values:
        config[key] = values[key]

    with open(path, "wb") as f:
        config.write(outfile=f)

    filesystem.chmod(path, 0o600)
