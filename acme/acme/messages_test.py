"""Tests for acme.messages."""
import unittest

import mock

from acme import challenges
from acme import jose
from acme import test_util


CERT = test_util.load_comparable_cert('cert.der')
CSR = test_util.load_comparable_csr('csr.der')
KEY = test_util.load_rsa_private_key('rsa512_key.pem')


class ErrorTest(unittest.TestCase):
    """Tests for acme.messages.Error."""

    def setUp(self):
        from acme.messages import Error
        self.error = Error(
            detail='foo', typ='urn:acme:error:malformed', title='title')
        self.jobj = {
            'detail': 'foo',
            'title': 'some title',
            'type': 'urn:acme:error:malformed',
        }
        self.error_custom = Error(typ='custom', detail='bar')
        self.jobj_cusom = {'type': 'custom', 'detail': 'bar'}

    def test_default_typ(self):
        from acme.messages import Error
        self.assertEqual(Error().typ, 'about:blank')

    def test_from_json_empty(self):
        from acme.messages import Error
        self.assertEqual(Error(), Error.from_json('{}'))

    def test_from_json_hashable(self):
        from acme.messages import Error
        hash(Error.from_json(self.error.to_json()))

    def test_description(self):
        self.assertEqual(
            'The request message was malformed', self.error.description)
        self.assertTrue(self.error_custom.description is None)

    def test_str(self):
        self.assertEqual(
            'urn:acme:error:malformed :: The request message was '
            'malformed :: foo :: title', str(self.error))
        self.assertEqual('custom :: bar', str(self.error_custom))


class ConstantTest(unittest.TestCase):
    """Tests for acme.messages._Constant."""

    def setUp(self):
        from acme.messages import _Constant

        class MockConstant(_Constant):  # pylint: disable=missing-docstring
            POSSIBLE_NAMES = {}

        self.MockConstant = MockConstant  # pylint: disable=invalid-name
        self.const_a = MockConstant('a')
        self.const_b = MockConstant('b')

    def test_to_partial_json(self):
        self.assertEqual('a', self.const_a.to_partial_json())
        self.assertEqual('b', self.const_b.to_partial_json())

    def test_from_json(self):
        self.assertEqual(self.const_a, self.MockConstant.from_json('a'))
        self.assertRaises(
            jose.DeserializationError, self.MockConstant.from_json, 'c')

    def test_from_json_hashable(self):
        hash(self.MockConstant.from_json('a'))

    def test_repr(self):
        self.assertEqual('MockConstant(a)', repr(self.const_a))
        self.assertEqual('MockConstant(b)', repr(self.const_b))

    def test_equality(self):
        const_a_prime = self.MockConstant('a')
        self.assertFalse(self.const_a == self.const_b)
        self.assertTrue(self.const_a == const_a_prime)

        self.assertTrue(self.const_a != self.const_b)
        self.assertFalse(self.const_a != const_a_prime)


class DirectoryTest(unittest.TestCase):
    """Tests for acme.messages.Directory."""

    def setUp(self):
        from acme.messages import Directory
        self.dir = Directory({
            'new-reg': 'reg',
            mock.MagicMock(resource_type='new-cert'): 'cert',
            'meta': Directory.Meta(
                terms_of_service='https://example.com/acme/terms',
                website='https://www.example.com/',
                caa_identities=['example.com'],
            ),
        })

    def test_init_wrong_key_value_success(self):  # pylint: disable=no-self-use
        from acme.messages import Directory
        Directory({'foo': 'bar'})

    def test_getitem(self):
        self.assertEqual('reg', self.dir['new-reg'])
        from acme.messages import NewRegistration
        self.assertEqual('reg', self.dir[NewRegistration])
        self.assertEqual('reg', self.dir[NewRegistration()])

    def test_getitem_fails_with_key_error(self):
        self.assertRaises(KeyError, self.dir.__getitem__, 'foo')

    def test_getattr(self):
        self.assertEqual('reg', self.dir.new_reg)

    def test_getattr_fails_with_attribute_error(self):
        self.assertRaises(AttributeError, self.dir.__getattr__, 'foo')

    def test_to_json(self):
        self.assertEqual(self.dir.to_json(), {
            'new-reg': 'reg',
            'new-cert': 'cert',
            'meta': {
                'terms-of-service': 'https://example.com/acme/terms',
                'website': 'https://www.example.com/',
                'caa-identities': ['example.com'],
            },
        })

    def test_from_json_deserialization_unknown_key_success(self):  # pylint: disable=no-self-use
        from acme.messages import Directory
        Directory.from_json({'foo': 'bar'})


class RegistrationTest(unittest.TestCase):
    """Tests for acme.messages.Registration."""

    def setUp(self):
        key = jose.jwk.JWKRSA(key=KEY.public_key())
        contact = (
            'mailto:admin@foo.com',
            'tel:1234',
        )
        agreement = 'https://letsencrypt.org/terms'

        from acme.messages import Registration
        self.reg = Registration(key=key, contact=contact, agreement=agreement)
        self.reg_none = Registration(authorizations='uri/authorizations',
                                     certificates='uri/certificates')

        self.jobj_to = {
            'contact': contact,
            'agreement': agreement,
            'key': key,
        }
        self.jobj_from = self.jobj_to.copy()
        self.jobj_from['key'] = key.to_json()

    def test_from_data(self):
        from acme.messages import Registration
        reg = Registration.from_data(phone='1234', email='admin@foo.com')
        self.assertEqual(reg.contact, (
            'tel:1234',
            'mailto:admin@foo.com',
        ))

    def test_phones(self):
        self.assertEqual(('1234',), self.reg.phones)

    def test_emails(self):
        self.assertEqual(('admin@foo.com',), self.reg.emails)

    def test_to_partial_json(self):
        self.assertEqual(self.jobj_to, self.reg.to_partial_json())

    def test_from_json(self):
        from acme.messages import Registration
        self.assertEqual(self.reg, Registration.from_json(self.jobj_from))

    def test_from_json_hashable(self):
        from acme.messages import Registration
        hash(Registration.from_json(self.jobj_from))


class UpdateRegistrationTest(unittest.TestCase):
    """Tests for acme.messages.UpdateRegistration."""

    def test_empty(self):
        from acme.messages import UpdateRegistration
        jstring = '{"resource": "reg"}'
        self.assertEqual(jstring, UpdateRegistration().json_dumps())
        self.assertEqual(
            UpdateRegistration(), UpdateRegistration.json_loads(jstring))


class RegistrationResourceTest(unittest.TestCase):
    """Tests for acme.messages.RegistrationResource."""

    def setUp(self):
        from acme.messages import RegistrationResource
        self.regr = RegistrationResource(
            body=mock.sentinel.body, uri=mock.sentinel.uri,
            new_authzr_uri=mock.sentinel.new_authzr_uri,
            terms_of_service=mock.sentinel.terms_of_service)

    def test_to_partial_json(self):
        self.assertEqual(self.regr.to_json(), {
            'body': mock.sentinel.body,
            'uri': mock.sentinel.uri,
            'new_authzr_uri': mock.sentinel.new_authzr_uri,
            'terms_of_service': mock.sentinel.terms_of_service,
        })


class ChallengeResourceTest(unittest.TestCase):
    """Tests for acme.messages.ChallengeResource."""

    def test_uri(self):
        from acme.messages import ChallengeResource
        self.assertEqual('http://challb', ChallengeResource(body=mock.MagicMock(
            uri='http://challb'), authzr_uri='http://authz').uri)


class ChallengeBodyTest(unittest.TestCase):
    """Tests for acme.messages.ChallengeBody."""

    def setUp(self):
        self.chall = challenges.DNS(token=jose.b64decode(
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA'))

        from acme.messages import ChallengeBody
        from acme.messages import Error
        from acme.messages import STATUS_INVALID
        self.status = STATUS_INVALID
        error = Error(typ='urn:acme:error:serverInternal',
                      detail='Unable to communicate with DNS server')
        self.challb = ChallengeBody(
            uri='http://challb', chall=self.chall, status=self.status,
            error=error)

        self.jobj_to = {
            'uri': 'http://challb',
            'status': self.status,
            'type': 'dns',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA',
            'error': error,
        }
        self.jobj_from = self.jobj_to.copy()
        self.jobj_from['status'] = 'invalid'
        self.jobj_from['error'] = {
            'type': 'urn:acme:error:serverInternal',
            'detail': 'Unable to communicate with DNS server',
        }

    def test_to_partial_json(self):
        self.assertEqual(self.jobj_to, self.challb.to_partial_json())

    def test_from_json(self):
        from acme.messages import ChallengeBody
        self.assertEqual(self.challb, ChallengeBody.from_json(self.jobj_from))

    def test_from_json_hashable(self):
        from acme.messages import ChallengeBody
        hash(ChallengeBody.from_json(self.jobj_from))

    def test_proxy(self):
        self.assertEqual(jose.b64decode(
            'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA'), self.challb.token)


class AuthorizationTest(unittest.TestCase):
    """Tests for acme.messages.Authorization."""

    def setUp(self):
        from acme.messages import ChallengeBody
        from acme.messages import STATUS_VALID

        self.challbs = (
            ChallengeBody(
                uri='http://challb1', status=STATUS_VALID,
                chall=challenges.HTTP01(token=b'IlirfxKKXAsHtmzK29Pj8A')),
            ChallengeBody(uri='http://challb2', status=STATUS_VALID,
                          chall=challenges.DNS(
                              token=b'DGyRejmCefe7v4NfDGDKfA')),
        )
        combinations = ((0,), (1,))

        from acme.messages import Authorization
        from acme.messages import Identifier
        from acme.messages import IDENTIFIER_FQDN
        identifier = Identifier(typ=IDENTIFIER_FQDN, value='example.com')
        self.authz = Authorization(
            identifier=identifier, combinations=combinations,
            challenges=self.challbs)

        self.jobj_from = {
            'identifier': identifier.to_json(),
            'challenges': [challb.to_json() for challb in self.challbs],
            'combinations': combinations,
        }

    def test_from_json(self):
        from acme.messages import Authorization
        Authorization.from_json(self.jobj_from)

    def test_from_json_hashable(self):
        from acme.messages import Authorization
        hash(Authorization.from_json(self.jobj_from))

    def test_resolved_combinations(self):
        self.assertEqual(self.authz.resolved_combinations, (
            (self.challbs[0],),
            (self.challbs[1],),
        ))


class AuthorizationResourceTest(unittest.TestCase):
    """Tests for acme.messages.AuthorizationResource."""

    def test_json_de_serializable(self):
        from acme.messages import AuthorizationResource
        authzr = AuthorizationResource(
            uri=mock.sentinel.uri,
            body=mock.sentinel.body,
            new_cert_uri=mock.sentinel.new_cert_uri,
        )
        self.assertTrue(isinstance(authzr, jose.JSONDeSerializable))


class CertificateRequestTest(unittest.TestCase):
    """Tests for acme.messages.CertificateRequest."""

    def setUp(self):
        from acme.messages import CertificateRequest
        self.req = CertificateRequest(csr=CSR)

    def test_json_de_serializable(self):
        self.assertTrue(isinstance(self.req, jose.JSONDeSerializable))
        from acme.messages import CertificateRequest
        self.assertEqual(
            self.req, CertificateRequest.from_json(self.req.to_json()))


class CertificateResourceTest(unittest.TestCase):
    """Tests for acme.messages.CertificateResourceTest."""

    def setUp(self):
        from acme.messages import CertificateResource
        self.certr = CertificateResource(
            body=CERT, uri=mock.sentinel.uri, authzrs=(),
            cert_chain_uri=mock.sentinel.cert_chain_uri)

    def test_json_de_serializable(self):
        self.assertTrue(isinstance(self.certr, jose.JSONDeSerializable))
        from acme.messages import CertificateResource
        self.assertEqual(
            self.certr, CertificateResource.from_json(self.certr.to_json()))


class RevocationTest(unittest.TestCase):
    """Tests for acme.messages.RevocationTest."""

    def setUp(self):
        from acme.messages import Revocation
        self.rev = Revocation(certificate=CERT)

    def test_from_json_hashable(self):
        from acme.messages import Revocation
        hash(Revocation.from_json(self.rev.to_json()))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
