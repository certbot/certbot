"""Tests for josepy.jws."""
import base64
import unittest

import mock
import OpenSSL

from josepy import errors, json_util, jwa, jwk, test_util

CERT = test_util.load_comparable_cert('cert.pem')
KEY = jwk.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))


class MediaTypeTest(unittest.TestCase):
    """Tests for josepy.jws.MediaType."""

    def test_decode(self):
        from josepy.jws import MediaType
        self.assertEqual('application/app', MediaType.decode('application/app'))
        self.assertEqual('application/app', MediaType.decode('app'))
        self.assertRaises(
            errors.DeserializationError, MediaType.decode, 'app;foo')

    def test_encode(self):
        from josepy.jws import MediaType
        self.assertEqual('app', MediaType.encode('application/app'))
        self.assertEqual('application/app;foo',
                         MediaType.encode('application/app;foo'))


class HeaderTest(unittest.TestCase):
    """Tests for josepy.jws.Header."""

    def setUp(self):
        from josepy.jws import Header
        self.header1 = Header(jwk='foo')
        self.header2 = Header(jwk='bar')
        self.crit = Header(crit=('a', 'b'))
        self.empty = Header()

    def test_add_non_empty(self):
        from josepy.jws import Header
        self.assertEqual(Header(jwk='foo', crit=('a', 'b')),
                         self.header1 + self.crit)

    def test_add_empty(self):
        self.assertEqual(self.header1, self.header1 + self.empty)
        self.assertEqual(self.header1, self.empty + self.header1)

    def test_add_overlapping_error(self):
        self.assertRaises(TypeError, self.header1.__add__, self.header2)

    def test_add_wrong_type_error(self):
        self.assertRaises(TypeError, self.header1.__add__, 'xxx')

    def test_crit_decode_always_errors(self):
        from josepy.jws import Header
        self.assertRaises(errors.DeserializationError, Header.from_json,
                          {'crit': ['a', 'b']})

    def test_x5c_decoding(self):
        from josepy.jws import Header
        header = Header(x5c=(CERT, CERT))
        jobj = header.to_partial_json()
        cert_asn1 = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, CERT.wrapped)
        cert_b64 = base64.b64encode(cert_asn1)
        self.assertEqual(jobj, {'x5c': [cert_b64, cert_b64]})
        self.assertEqual(header, Header.from_json(jobj))
        jobj['x5c'][0] = base64.b64encode(b'xxx' + cert_asn1)
        self.assertRaises(errors.DeserializationError, Header.from_json, jobj)

    def test_find_key(self):
        self.assertEqual('foo', self.header1.find_key())
        self.assertEqual('bar', self.header2.find_key())
        self.assertRaises(errors.Error, self.crit.find_key)


class SignatureTest(unittest.TestCase):
    """Tests for josepy.jws.Signature."""

    def test_from_json(self):
        from josepy.jws import Header
        from josepy.jws import Signature
        self.assertEqual(
            Signature(signature=b'foo', header=Header(alg=jwa.RS256)),
            Signature.from_json(
                {'signature': 'Zm9v', 'header': {'alg': 'RS256'}}))

    def test_from_json_no_alg_error(self):
        from josepy.jws import Signature
        self.assertRaises(errors.DeserializationError,
                          Signature.from_json, {'signature': 'foo'})


class JWSTest(unittest.TestCase):
    """Tests for josepy.jws.JWS."""

    def setUp(self):
        self.privkey = KEY
        self.pubkey = self.privkey.public_key()

        from josepy.jws import JWS
        self.unprotected = JWS.sign(
            payload=b'foo', key=self.privkey, alg=jwa.RS256)
        self.protected = JWS.sign(
            payload=b'foo', key=self.privkey, alg=jwa.RS256,
            protect=frozenset(['jwk', 'alg']))
        self.mixed = JWS.sign(
            payload=b'foo', key=self.privkey, alg=jwa.RS256,
            protect=frozenset(['alg']))

    def test_pubkey_jwk(self):
        self.assertEqual(self.unprotected.signature.combined.jwk, self.pubkey)
        self.assertEqual(self.protected.signature.combined.jwk, self.pubkey)
        self.assertEqual(self.mixed.signature.combined.jwk, self.pubkey)

    def test_sign_unprotected(self):
        self.assertTrue(self.unprotected.verify())

    def test_sign_protected(self):
        self.assertTrue(self.protected.verify())

    def test_sign_mixed(self):
        self.assertTrue(self.mixed.verify())

    def test_compact_lost_unprotected(self):
        compact = self.mixed.to_compact()
        self.assertEqual(
            b'eyJhbGciOiAiUlMyNTYifQ.Zm9v.OHdxFVj73l5LpxbFp1AmYX4yJM0Pyb'
            b'_893n1zQjpim_eLS5J1F61lkvrCrCDErTEJnBGOGesJ72M7b6Ve1cAJA',
            compact)

        from josepy.jws import JWS
        mixed = JWS.from_compact(compact)

        self.assertNotEqual(self.mixed, mixed)
        self.assertEqual(
            set(['alg']), set(mixed.signature.combined.not_omitted()))

    def test_from_compact_missing_components(self):
        from josepy.jws import JWS
        self.assertRaises(errors.DeserializationError, JWS.from_compact, b'.')

    def test_json_omitempty(self):
        protected_jobj = self.protected.to_partial_json(flat=True)
        unprotected_jobj = self.unprotected.to_partial_json(flat=True)

        self.assertTrue('protected' not in unprotected_jobj)
        self.assertTrue('header' not in protected_jobj)

        unprotected_jobj['header'] = unprotected_jobj['header'].to_json()

        from josepy.jws import JWS
        self.assertEqual(JWS.from_json(protected_jobj), self.protected)
        self.assertEqual(JWS.from_json(unprotected_jobj), self.unprotected)

    def test_json_flat(self):
        jobj_to = {
            'signature': json_util.encode_b64jose(
                self.mixed.signature.signature),
            'payload': json_util.encode_b64jose(b'foo'),
            'header': self.mixed.signature.header,
            'protected': json_util.encode_b64jose(
                self.mixed.signature.protected.encode('utf-8')),
        }
        jobj_from = jobj_to.copy()
        jobj_from['header'] = jobj_from['header'].to_json()

        self.assertEqual(self.mixed.to_partial_json(flat=True), jobj_to)
        from josepy.jws import JWS
        self.assertEqual(self.mixed, JWS.from_json(jobj_from))

    def test_json_not_flat(self):
        jobj_to = {
            'signatures': (self.mixed.signature,),
            'payload': json_util.encode_b64jose(b'foo'),
        }
        jobj_from = jobj_to.copy()
        jobj_from['signatures'] = [jobj_to['signatures'][0].to_json()]

        self.assertEqual(self.mixed.to_partial_json(flat=False), jobj_to)
        from josepy.jws import JWS
        self.assertEqual(self.mixed, JWS.from_json(jobj_from))

    def test_from_json_mixed_flat(self):
        from josepy.jws import JWS
        self.assertRaises(errors.DeserializationError, JWS.from_json,
                          {'signatures': (), 'signature': 'foo'})

    def test_from_json_hashable(self):
        from josepy.jws import JWS
        hash(JWS.from_json(self.mixed.to_json()))


class CLITest(unittest.TestCase):

    def setUp(self):
        self.key_path = test_util.vector_path('rsa512_key.pem')

    def test_unverified(self):
        from josepy.jws import CLI
        with mock.patch('sys.stdin') as sin:
            sin.read.return_value = '{"payload": "foo", "signature": "xxx"}'
            with mock.patch('sys.stdout'):
                self.assertEqual(-1, CLI.run(['verify']))

    def test_json(self):
        from josepy.jws import CLI

        with mock.patch('sys.stdin') as sin:
            sin.read.return_value = 'foo'
            with mock.patch('sys.stdout') as sout:
                CLI.run(['sign', '-k', self.key_path, '-a', 'RS256',
                         '-p', 'jwk'])
                sin.read.return_value = sout.write.mock_calls[0][1][0]
                self.assertEqual(0, CLI.run(['verify']))

    def test_compact(self):
        from josepy.jws import CLI

        with mock.patch('sys.stdin') as sin:
            sin.read.return_value = 'foo'
            with mock.patch('sys.stdout') as sout:
                CLI.run(['--compact', 'sign', '-k', self.key_path])
                sin.read.return_value = sout.write.mock_calls[0][1][0]
                self.assertEqual(0, CLI.run([
                    '--compact', 'verify', '--kty', 'RSA',
                    '-k', self.key_path]))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
