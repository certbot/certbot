"""Base test class for DNS authenticators."""

import os

import configobj
import josepy as jose
import mock
import six
from acme import challenges

from certbot import achallenges
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
        # pylint: disable=no-member
        self.assertTrue(isinstance(self.auth.more_info(), six.string_types))

    def test_get_chall_pref(self):
        # pylint: disable=no-member
        self.assertEqual(self.auth.get_chall_pref(None), [challenges.DNS01])

    def test_parser_arguments(self):
        m = mock.MagicMock()

        # pylint: disable=no-member
        self.auth.add_parser_arguments(m)

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

    os.chmod(path, 0o600)
