"""Tests for letsencrypt.acme.jose.jws."""
import base64
import os
import pkg_resources
import unittest

import Crypto.PublicKey.RSA
import M2Crypto.X509
import mock

from letsencrypt.acme.jose import b64
from letsencrypt.acme.jose import errors
from letsencrypt.acme.jose import jwa
from letsencrypt.acme.jose import jwk
from letsencrypt.acme.jose import util


CERT = util.ComparableX509(M2Crypto.X509.load_cert(
    pkg_resources.resource_filename(
        'letsencrypt.client.tests', 'testdata/cert.pem')))
RSA512_KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    __name__, os.path.join('testdata', 'rsa512_key.pem')))


class MediaTypeTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.jws.MediaType."""

    def test_decode(self):
        from letsencrypt.acme.jose.jws import MediaType
        self.assertEqual('application/app', MediaType.decode('application/app'))
        self.assertEqual('application/app', MediaType.decode('app'))
        self.assertRaises(
            errors.DeserializationError, MediaType.decode, 'app;foo')

    def test_encode(self):
        from letsencrypt.acme.jose.jws import MediaType
        self.assertEqual('app', MediaType.encode('application/app'))
        self.assertEqual('application/app;foo',
                         MediaType.encode('application/app;foo'))


class HeaderTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.jws.Header."""

    def setUp(self):
        from letsencrypt.acme.jose.jws import Header
        self.header1 = Header(jwk='foo')
        self.header2 = Header(jwk='bar')
        self.crit = Header(crit=('a', 'b'))
        self.empty = Header()

    def test_add_non_empty(self):
        from letsencrypt.acme.jose.jws import Header
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
        from letsencrypt.acme.jose.jws import Header
        self.assertRaises(errors.DeserializationError, Header.from_json,
                          {'crit': ['a', 'b']})

    def test_x5c_decoding(self):
        from letsencrypt.acme.jose.jws import Header
        header = Header(x5c=(CERT, CERT))
        jobj = header.to_json()
        cert_b64 = base64.b64encode(CERT.as_der())
        self.assertEqual(jobj, {'x5c': [cert_b64, cert_b64]})
        self.assertEqual(header, Header.from_json(jobj))
        jobj['x5c'][0] = base64.b64encode('xxx' + CERT.as_der())
        self.assertRaises(errors.DeserializationError, Header.from_json, jobj)

    def test_find_key(self):
        self.assertEqual('foo', self.header1.find_key())
        self.assertEqual('bar', self.header2.find_key())
        self.assertRaises(errors.Error, self.crit.find_key)


class SignatureTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.jws.Signature."""

    def test_from_json(self):
        from letsencrypt.acme.jose.jws import Header
        from letsencrypt.acme.jose.jws import Signature
        self.assertEqual(
            Signature(signature='foo', header=Header(alg=jwa.RS256)),
            Signature.from_json(
                {'signature': 'Zm9v', 'header': {'alg': 'RS256'}}))

    def test_from_json_no_alg_error(self):
        from letsencrypt.acme.jose.jws import Signature
        self.assertRaises(errors.DeserializationError,
                          Signature.from_json, {'signature': 'foo'})


class JWSTest(unittest.TestCase):
    """Tests for letsencrypt.acme.jose.jws.JWS."""

    def setUp(self):
        self.privkey = jwk.JWKRSA(key=RSA512_KEY)
        self.pubkey = self.privkey.public()

        from letsencrypt.acme.jose.jws import JWS
        self.unprotected = JWS.sign(
            payload='foo', key=self.privkey, alg=jwa.RS256)
        self.protected = JWS.sign(
            payload='foo', key=self.privkey, alg=jwa.RS256,
            protect=frozenset(['jwk', 'alg']))
        self.mixed = JWS.sign(
            payload='foo', key=self.privkey, alg=jwa.RS256,
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
            'eyJhbGciOiAiUlMyNTYifQ.Zm9v.KBvYScRMEqJlp2xsReoY3CNDpVCWEU'
            '1PyRrf44nPBsmyQz__iuNR56pPNcACeHzJQnXhTVTxqFgjge2i_vw9NA',
            compact)

        from letsencrypt.acme.jose.jws import JWS
        mixed = JWS.from_compact(compact)

        self.assertNotEqual(self.mixed, mixed)
        self.assertEqual(
            set(['alg']), set(mixed.signature.combined.not_omitted()))

    def test_from_compact_missing_components(self):
        from letsencrypt.acme.jose.jws import JWS
        self.assertRaises(errors.DeserializationError, JWS.from_compact, '.')

    def test_json_omitempty(self):
        protected_jobj = self.protected.to_json(flat=True)
        unprotected_jobj = self.unprotected.to_json(flat=True)

        self.assertTrue('protected' not in unprotected_jobj)
        self.assertTrue('header' not in protected_jobj)

        unprotected_jobj['header'] = unprotected_jobj[
            'header'].fully_serialize()

        from letsencrypt.acme.jose.jws import JWS
        self.assertEqual(JWS.from_json(protected_jobj), self.protected)
        self.assertEqual(JWS.from_json(unprotected_jobj), self.unprotected)

    def test_json_flat(self):
        jobj_to = {
            'signature': b64.b64encode(self.mixed.signature.signature),
            'payload': b64.b64encode('foo'),
            'header': self.mixed.signature.header,
            'protected': b64.b64encode(self.mixed.signature.protected),
        }
        jobj_from = jobj_to.copy()
        jobj_from['header'] = jobj_from['header'].fully_serialize()

        self.assertEqual(self.mixed.to_json(flat=True), jobj_to)
        from letsencrypt.acme.jose.jws import JWS
        self.assertEqual(self.mixed, JWS.from_json(jobj_from))

    def test_json_not_flat(self):
        jobj_to = {
            'signatures': (self.mixed.signature,),
            'payload': b64.b64encode('foo'),
        }
        jobj_from = jobj_to.copy()
        jobj_from['signatures'] = [jobj_to['signatures'][0].fully_serialize()]

        self.assertEqual(self.mixed.to_json(flat=False), jobj_to)
        from letsencrypt.acme.jose.jws import JWS
        self.assertEqual(self.mixed, JWS.from_json(jobj_from))

    def test_from_json_mixed_flat(self):
        from letsencrypt.acme.jose.jws import JWS
        self.assertRaises(errors.DeserializationError, JWS.from_json,
                          {'signatures': (), 'signature': 'foo'})


class CLITest(unittest.TestCase):

    def setUp(self):
        self.key_path = pkg_resources.resource_filename(
            __name__, os.path.join('testdata', 'rsa512_key.pem'))

    def test_unverified(self):
        from letsencrypt.acme.jose.jws import CLI
        with mock.patch('sys.stdin') as sin:
            sin.read.return_value = '{"payload": "foo", "signature": "xxx"}'
            with mock.patch('sys.stdout'):
                self.assertEqual(-1, CLI.run(['verify']))

    def test_json(self):
        from letsencrypt.acme.jose.jws import CLI

        with mock.patch('sys.stdin') as sin:
            sin.read.return_value = 'foo'
            with mock.patch('sys.stdout') as sout:
                CLI.run(['sign', '-k', self.key_path, '-a', 'RS256',
                         '-p', 'jwk'])
                sin.read.return_value = sout.write.mock_calls[0][1][0]
                self.assertEqual(0, CLI.run(['verify']))

    def test_compact(self):
        from letsencrypt.acme.jose.jws import CLI

        with mock.patch('sys.stdin') as sin:
            sin.read.return_value = 'foo'
            with mock.patch('sys.stdout') as sout:
                CLI.run(['--compact', 'sign', '-k', self.key_path])
                sin.read.return_value = sout.write.mock_calls[0][1][0]
                self.assertEqual(0, CLI.run([
                    '--compact', 'verify', '--kty', 'RSA',
                    '-k', self.key_path]))


if __name__ == '__main__':
    unittest.main()
