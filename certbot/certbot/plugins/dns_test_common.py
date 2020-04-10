"""Base test class for DNS authenticators."""

import configobj
import josepy as jose
try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
import six

from acme import challenges
from certbot import achallenges
from certbot.compat import filesystem
from certbot.tests import acme_util
from certbot.tests import util as test_util

DOMAIN = 'example.com'
KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class BaseAuthenticatorTest(object):
    """
    A base test class to reduce duplication between test code for DNS Authenticator Plugins.

    Assumes:
     * That subclasses also subclass unittest.TestCase
     * That the authenticator is stored as self.auth
    """

    achall = achallenges.KeyAuthorizationAnnotatedChallenge(
        challb=acme_util.DNS01, domain=DOMAIN, account_key=KEY)

    def test_more_info(self):
        self.assertTrue(isinstance(self.auth.more_info(), six.string_types))  # pylint: disable=no-member

    def test_get_chall_pref(self):
        self.assertEqual(self.auth.get_chall_pref(None), [challenges.DNS01])  # pylint: disable=no-member

    def test_parser_arguments(self):
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
