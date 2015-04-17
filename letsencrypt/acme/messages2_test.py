"""Tests for letsencrypt.acme.messages2."""
import datetime
import os
import pkg_resources
import unittest

import mock
import pytz
from Crypto.PublicKey import RSA

from letsencrypt.acme import challenges
from letsencrypt.acme import jose


class ErrorTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages2.Error."""

    def setUp(self):
        from letsencrypt.acme.messages2 import Error
        self.error = Error(detail='foo', typ='malformed')

    def test_typ_prefix(self):
        self.assertEqual('malformed', self.error.typ)
        self.assertEqual(
            'urn:acme:error:malformed', self.error.to_json()['type'])
        self.assertEqual(
            'malformed', self.error.from_json(self.error.to_json()).typ)

    def test_typ_decoder_missing_prefix(self):
        from letsencrypt.acme.messages2 import Error
        self.assertRaises(jose.DeserializationError, Error.from_json,
                          {'detail': 'foo', 'type': 'malformed'})
        self.assertRaises(jose.DeserializationError, Error.from_json,
                          {'detail': 'foo', 'type': 'not valid bare type'})

    def test_typ_decoder_not_recognized(self):
        from letsencrypt.acme.messages2 import Error
        self.assertRaises(jose.DeserializationError, Error.from_json,
                          {'detail': 'foo', 'type': 'urn:acme:error:baz'})

    def test_description(self):
        self.assertEqual(
            'The request message was malformed', self.error.description)

    def test_from_json_hashable(self):
        from letsencrypt.acme.messages2 import Error
        hash(Error.from_json(self.error.fully_serialize()))


class ConstantTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages2._Constant."""

    def setUp(self):
        from letsencrypt.acme.messages2 import _Constant
        class MockConstant(_Constant):  # pylint: disable=missing-docstring
            POSSIBLE_NAMES = {}

        self.MockConstant = MockConstant  # pylint: disable=invalid-name
        self.const_a = MockConstant('a')
        self.const_b = MockConstant('b')

    def test_to_json(self):
        self.assertEqual('a', self.const_a.to_json())
        self.assertEqual('b', self.const_b.to_json())

    def test_from_json(self):
        self.assertEqual(self.const_a, self.MockConstant.from_json('a'))
        self.assertRaises(
            jose.DeserializationError, self.MockConstant.from_json, 'c')

    def test_from_json_hashable(self):
        hash(self.MockConstant.from_json('a'))

    def test_repr(self):
        self.assertEqual('MockConstant(a)', repr(self.const_a))
        self.assertEqual('MockConstant(b)', repr(self.const_b))


class RegistrationTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages2.Registration."""

    def setUp(self):
        from letsencrypt.acme.messages2 import Registration

        rsa_key = RSA.importKey(pkg_resources.resource_string(
            'letsencrypt.client.tests', os.path.join(
                'testdata', 'rsa256_key.pem')))

        self.key = jose.jwk.JWKRSA(key=jose.util.HashableRSAKey(
            rsa_key.publickey()))

        self.contact = ("mailto:letsencrypt-client@letsencrypt.org",)
        self.recovery_token = "XYZ"
        self.agreement = "https://letsencrypt.org/terms"
        self.reg = Registration(
            key=self.key, contact=self.contact,
            recovery_token=self.recovery_token, agreement=self.agreement)

        self.json_key = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                 '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
        }

        self.json_reg = {
            "contact": self.contact,
            "recoveryToken": self.recovery_token,
            "agreement": self.agreement,
            "key": self.json_key,
        }

    def test_to_json(self):
        self.assertEqual(self.reg.to_json(), self.json_reg)

    def test_from_json(self):
        from letsencrypt.acme.messages2 import Registration

        self.assertEqual(Registration.from_json(self.json_reg), self.reg)

class ChallengeResourceTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages2.ChallengeResource."""

    def test_uri(self):
        from letsencrypt.acme.messages2 import ChallengeResource
        self.assertEqual('http://challb', ChallengeResource(body=mock.MagicMock(
            uri='http://challb'), authzr_uri='http://authz').uri)


class ChallengeBodyTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages2.ChallengeBody."""

    def setUp(self):
        self.chall = challenges.DNS(token='foo')

        from letsencrypt.acme.messages2 import ChallengeBody
        from letsencrypt.acme.messages2 import STATUS_VALID
        self.status = STATUS_VALID
        self.challb = ChallengeBody(
            uri='http://challb', chall=self.chall, status=self.status)

        self.jobj_to = {
            'uri': 'http://challb',
            'status': self.status,
            'type': 'dns',
            'token': 'foo',
        }
        self.jobj_from = self.jobj_to.copy()
        self.jobj_from['status'] = 'valid'

    def test_to_json(self):
        self.assertEqual(self.jobj_to, self.challb.to_json())

    def test_from_json(self):
        from letsencrypt.acme.messages2 import ChallengeBody
        self.assertEqual(self.challb, ChallengeBody.from_json(self.jobj_from))

    def test_from_json_hashable(self):
        from letsencrypt.acme.messages2 import ChallengeBody
        hash(ChallengeBody.from_json(self.jobj_from))


class AuthorizationTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages2.Authorization."""

    def setUp(self):
        from letsencrypt.acme.messages2 import ChallengeBody
        from letsencrypt.acme.messages2 import STATUS_VALID
        self.challbs = (
            ChallengeBody(
                uri='http://challb1', status=STATUS_VALID,
                chall=challenges.SimpleHTTPS(token='IlirfxKKXAsHtmzK29Pj8A')),
            ChallengeBody(uri='http://challb2', status=STATUS_VALID,
                          chall=challenges.DNS(token='DGyRejmCefe7v4NfDGDKfA')),
            ChallengeBody(uri='http://challb3', status=STATUS_VALID,
                          chall=challenges.RecoveryToken()),
        )
        combinations = ((0, 2), (1, 2))

        from letsencrypt.acme.messages2 import Authorization
        from letsencrypt.acme.messages2 import Identifier
        from letsencrypt.acme.messages2 import IDENTIFIER_FQDN
        identifier = Identifier(typ=IDENTIFIER_FQDN, value='example.com')
        self.authz = Authorization(
            identifier=identifier, combinations=combinations,
            challenges=self.challbs)

        self.jobj_from = {
            'identifier': identifier.fully_serialize(),
            'challenges': [challb.fully_serialize() for challb in self.challbs],
            'combinations': combinations,
        }

    def test_from_json(self):
        from letsencrypt.acme.messages2 import Authorization
        Authorization.from_json(self.jobj_from)

    def test_from_json_hashable(self):
        from letsencrypt.acme.messages2 import Authorization
        hash(Authorization.from_json(self.jobj_from))

    def test_resolved_combinations(self):
        self.assertEqual(self.authz.resolved_combinations, (
            (self.challbs[0], self.challbs[2]),
            (self.challbs[1], self.challbs[2]),
        ))


class RevocationTest(unittest.TestCase):
    """Tests for letsencrypt.acme.messages2.RevocationTest."""

    def setUp(self):
        from letsencrypt.acme.messages2 import Revocation
        self.rev_now = Revocation(authorizations=(), revoke=Revocation.NOW)
        self.rev_date = Revocation(authorizations=(), revoke=datetime.datetime(
            2015, 3, 27, tzinfo=pytz.utc))
        self.jobj_now = {'authorizations': (), 'revoke': Revocation.NOW}
        self.jobj_date = {'authorizations': (),
                          'revoke': '2015-03-27T00:00:00Z'}

    def test_revoke_decoder(self):
        from letsencrypt.acme.messages2 import Revocation
        self.assertEqual(self.rev_now, Revocation.from_json(self.jobj_now))
        self.assertEqual(self.rev_date, Revocation.from_json(self.jobj_date))

    def test_revoke_encoder(self):
        self.assertEqual(self.jobj_now, self.rev_now.to_json())
        self.assertEqual(self.jobj_date, self.rev_date.to_json())

    def test_from_json_hashable(self):
        from letsencrypt.acme.messages2 import Revocation
        hash(Revocation.from_json(self.rev_now.fully_serialize()))


if __name__ == '__main__':
    unittest.main()
