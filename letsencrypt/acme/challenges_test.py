"""Tests for letsencrypt.acme.challenges."""
import os
import pkg_resources
import unittest

import Crypto.PublicKey.RSA
import M2Crypto

from letsencrypt.acme import errors
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.acme import util


CERT = util.ComparableX509(M2Crypto.X509.load_cert(
    pkg_resources.resource_filename(
        'letsencrypt.client.tests', 'testdata/cert.pem')))
KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    'letsencrypt.client.tests', os.path.join('testdata', 'rsa256_key.pem')))


class SimpleHTTPSTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import SimpleHTTPS
        self.msg = SimpleHTTPS(
            token='evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA')
        self.jmsg = {
            'type': 'simpleHttps',
            'token': 'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA',
        }

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import SimpleHTTPS
        self.assertEqual(self.msg, SimpleHTTPS.from_valid_json(self.jmsg))


class SimpleHTTPSResponseTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import SimpleHTTPSResponse
        self.msg = SimpleHTTPSResponse(path='6tbIMBC5Anhl5bOlWT5ZFA')
        self.jmsg = {
            'type': 'simpleHttps',
            'path': '6tbIMBC5Anhl5bOlWT5ZFA',
        }

    def test_uri(self):
        self.assertEqual('https://example.com/.well-known/acme-challenge/'
                         '6tbIMBC5Anhl5bOlWT5ZFA', self.msg.uri('example.com'))

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import SimpleHTTPSResponse
        self.assertEqual(
            self.msg, SimpleHTTPSResponse.from_valid_json(self.jmsg))


class DVSNITest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import DVSNI
        self.msg = DVSNI(
            r="O*\xb4-\xad\xec\x95>\xed\xa9\r0\x94\xe8\x97\x9c&6"
              "\xbf'\xb3\xed\x9a9nX\x0f'\\m\xe7\x12",
            nonce='\xa8-_\xf8\xeft\r\x12\x88\x1fm<"w\xab.')
        self.jmsg = {
            'type': 'dvsni',
            'r': 'Tyq0La3slT7tqQ0wlOiXnCY2vyez7Zo5blgPJ1xt5xI',
            'nonce': 'a82d5ff8ef740d12881f6d3c2277ab2e',
        }

    def test_nonce_domain(self):
        self.assertEqual('a82d5ff8ef740d12881f6d3c2277ab2e.acme.invalid',
                         self.msg.nonce_domain)

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import DVSNI
        self.assertEqual(self.msg, DVSNI.from_valid_json(self.jmsg))

    def test_from_json_invalid_r_length(self):
        from letsencrypt.acme.challenges import DVSNI
        self.jmsg['r'] = 'abcd'
        self.assertRaises(
            errors.ValidationError, DVSNI.from_valid_json, self.jmsg)

    def test_from_json_invalid_nonce_length(self):
        from letsencrypt.acme.challenges import DVSNI
        self.jmsg['nonce'] = 'abcd'
        self.assertRaises(
            errors.ValidationError, DVSNI.from_valid_json, self.jmsg)


class DVSNIResponseTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import DVSNIResponse
        self.msg = DVSNIResponse(
            s='\xf5\xd6\xe3\xb2]\xe0L\x0bN\x9cKJ\x14I\xa1K\xa3#\xf9\xa8'
              '\xcd\x8c7\x0e\x99\x19)\xdc\xb7\xf3\x9bw')
        self.jmsg = {
            'type': 'dvsni',
            's': '9dbjsl3gTAtOnEtKFEmhS6Mj-ajNjDcOmRkp3Lfzm3c',
        }

    def test_z_and_domain(self):
        from letsencrypt.acme.challenges import DVSNI
        challenge = DVSNI(
            r="O*\xb4-\xad\xec\x95>\xed\xa9\r0\x94\xe8\x97\x9c&6"
              "\xbf'\xb3\xed\x9a9nX\x0f'\\m\xe7\x12",
            nonce=long('439736375371401115242521957580409149254868992063'
                       '44333654741504362774620418661L'))
        # pylint: disable=invalid-name
        z = '38e612b0397cc2624a07d351d7ef50e46134c0213d9ed52f7d7c611acaeed41b'
        self.assertEqual(z, self.msg.z(challenge))
        self.assertEqual(
            '{0}.acme.invalid'.format(z), self.msg.z_domain(challenge))

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import DVSNIResponse
        self.assertEqual(self.msg, DVSNIResponse.from_valid_json(self.jmsg))


class RecoveryContactTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import RecoveryContact
        self.msg = RecoveryContact(
            activation_url='https://example.ca/sendrecovery/a5bd99383fb0',
            success_url='https://example.ca/confirmrecovery/bb1b9928932',
            contact='c********n@example.com')
        self.jmsg = {
            'type': 'recoveryContact',
            'activationURL' : 'https://example.ca/sendrecovery/a5bd99383fb0',
            'successURL' : 'https://example.ca/confirmrecovery/bb1b9928932',
            'contact' : 'c********n@example.com',
        }

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import RecoveryContact
        self.assertEqual(self.msg, RecoveryContact.from_valid_json(self.jmsg))

    def test_json_without_optionals(self):
        del self.jmsg['activationURL']
        del self.jmsg['successURL']
        del self.jmsg['contact']

        from letsencrypt.acme.challenges import RecoveryContact
        msg = RecoveryContact.from_valid_json(self.jmsg)

        self.assertTrue(msg.activation_url is None)
        self.assertTrue(msg.success_url is None)
        self.assertTrue(msg.contact is None)
        self.assertEqual(self.jmsg, msg.to_json())


class RecoveryContactResponseTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import RecoveryContactResponse
        self.msg = RecoveryContactResponse(token='23029d88d9e123e')
        self.jmsg = {'type': 'recoveryContact', 'token': '23029d88d9e123e'}

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import RecoveryContactResponse
        self.assertEqual(
            self.msg, RecoveryContactResponse.from_valid_json(self.jmsg))

    def test_json_without_optionals(self):
        del self.jmsg['token']

        from letsencrypt.acme.challenges import RecoveryContactResponse
        msg = RecoveryContactResponse.from_valid_json(self.jmsg)

        self.assertTrue(msg.token is None)
        self.assertEqual(self.jmsg, msg.to_json())


class RecoveryTokenTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import RecoveryToken
        self.msg = RecoveryToken()
        self.jmsg = {'type': 'recoveryToken'}

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import RecoveryToken
        self.assertEqual(self.msg, RecoveryToken.from_valid_json(self.jmsg))


class RecoveryTokenResponseTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import RecoveryTokenResponse
        self.msg = RecoveryTokenResponse(token='23029d88d9e123e')
        self.jmsg = {'type': 'recoveryToken', 'token': '23029d88d9e123e'}

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import RecoveryTokenResponse
        self.assertEqual(
            self.msg, RecoveryTokenResponse.from_valid_json(self.jmsg))

    def test_json_without_optionals(self):
        del self.jmsg['token']

        from letsencrypt.acme.challenges import RecoveryTokenResponse
        msg = RecoveryTokenResponse.from_valid_json(self.jmsg)

        self.assertTrue(msg.token is None)
        self.assertEqual(self.jmsg, msg.to_json())


class ProofOfPossessionHintsTest(unittest.TestCase):

    def setUp(self):
        jwk = other.JWK(key=KEY.publickey())
        issuers = [
            'C=US, O=SuperT LLC, CN=SuperTrustworthy Public CA',
            'O=LessTrustworthy CA Inc, CN=LessTrustworthy But StillSecure',
        ]
        cert_fingerprints = [
            '93416768eb85e33adc4277f4c9acd63e7418fcfe',
            '16d95b7b63f1972b980b14c20291f3c0d1855d95',
            '48b46570d9fc6358108af43ad1649484def0debf',
        ]
        subject_key_identifiers = ['d0083162dcc4c8a23ecb8aecbd86120e56fd24e5']
        authorized_for = ['www.example.com', 'example.net']
        serial_numbers = [34234239832, 23993939911, 17]

        from letsencrypt.acme.challenges import ProofOfPossession
        self.msg = ProofOfPossession.Hints(
            jwk=jwk, issuers=issuers, cert_fingerprints=cert_fingerprints,
            certs=[CERT], subject_key_identifiers=subject_key_identifiers,
            authorized_for=authorized_for, serial_numbers=serial_numbers)

        self.jmsg_to = {
            'jwk': jwk,
            'certFingerprints': cert_fingerprints,
            'certs': [jose.b64encode(CERT.as_der())],
            'subjectKeyIdentifiers': subject_key_identifiers,
            'serialNumbers': serial_numbers,
            'issuers': issuers,
            'authorizedFor': authorized_for,
        }
        self.jmsg_from = self.jmsg_to.copy()
        self.jmsg_from.update({'jwk': jwk.to_json()})

    def test_to_json(self):
        self.assertEqual(self.jmsg_to, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import ProofOfPossession
        self.assertEqual(
            self.msg, ProofOfPossession.Hints.from_valid_json(self.jmsg_from))

    def test_json_without_optionals(self):
        for optional in ['certFingerprints', 'certs', 'subjectKeyIdentifiers',
                         'serialNumbers', 'issuers', 'authorizedFor']:
            del self.jmsg_from[optional]
            del self.jmsg_to[optional]

        from letsencrypt.acme.challenges import ProofOfPossession
        msg = ProofOfPossession.Hints.from_valid_json(self.jmsg_from)

        self.assertEqual(msg.cert_fingerprints, [])
        self.assertEqual(msg.certs, [])
        self.assertEqual(msg.subject_key_identifiers, [])
        self.assertEqual(msg.serial_numbers, [])
        self.assertEqual(msg.issuers, [])
        self.assertEqual(msg.authorized_for, [])

        self.assertEqual(self.jmsg_to, msg.to_json())


class ProofOfPossessionTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import ProofOfPossession
        hints = ProofOfPossession.Hints(
            jwk=other.JWK(key=KEY.publickey()), cert_fingerprints=[], certs=[],
            serial_numbers=[], subject_key_identifiers=[], issuers=[],
            authorized_for=[])
        self.msg = ProofOfPossession(
            alg='RS256', nonce='xD\xf9\xb9\xdbU\xed\xaa\x17\xf1y|\x81\x88\x99 ',
            hints=hints)

        self.jmsg_to = {
            'type': 'proofOfPossession',
            'alg': 'RS256',
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'hints': hints,
        }
        self.jmsg_from = {
            'type': 'proofOfPossession',
            'alg': 'RS256',
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'hints': hints.to_json(),
        }
        self.jmsg_from['hints']['jwk'] = self.jmsg_from[
            'hints']['jwk'].to_json()

    def test_to_json(self):
        self.assertEqual(self.jmsg_to, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import ProofOfPossession
        self.assertEqual(
            self.msg, ProofOfPossession.from_valid_json(self.jmsg_from))


class ProofOfPossessionResponseTest(unittest.TestCase):

    def setUp(self):
        # acme-spec uses a confusing example in which both signature
        # nonce and challenge nonce are the same, don't make the same
        # mistake here...
        signature = other.Signature(
            alg='RS256', jwk=other.JWK(key=KEY.publickey()),
            sig='\xa7\xc1\xe7\xe82o\xbc\xcd\xd0\x1e\x010#Z|\xaf\x15\x83'
                '\x94\x8f#\x9b\nQo(\x80\x15,\x08\xfcz\x1d\xfd\xfd.\xaap'
                '\xfa\x06\xd1\xa2f\x8d8X2>%d\xbd%\xe1T\xdd\xaa0\x18\xde'
                '\x99\x08\xf0\x0e{',
            nonce='\x99\xc7Q\xb3f2\xbc\xdci\xfe\xd6\x98k\xc67\xdf',
        )

        from letsencrypt.acme.challenges import ProofOfPossessionResponse
        self.msg = ProofOfPossessionResponse(
            nonce='xD\xf9\xb9\xdbU\xed\xaa\x17\xf1y|\x81\x88\x99 ',
            signature=signature)

        self.jmsg_to = {
            'type': 'proofOfPossession',
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'signature': signature,
        }
        self.jmsg_from = {
            'type': 'proofOfPossession',
            'nonce': 'eET5udtV7aoX8Xl8gYiZIA',
            'signature': signature.to_json(),
        }
        self.jmsg_from['signature']['jwk'] = self.jmsg_from[
            'signature']['jwk'].to_json()


    def test_verify(self):
        self.assertTrue(self.msg.verify())

    def test_to_json(self):
        self.assertEqual(self.jmsg_to, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import ProofOfPossessionResponse
        self.assertEqual(
            self.msg, ProofOfPossessionResponse.from_valid_json(self.jmsg_from))


class DNSTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import DNS
        self.msg = DNS(token='17817c66b60ce2e4012dfad92657527a')
        self.jmsg = {'type': 'dns', 'token': '17817c66b60ce2e4012dfad92657527a'}

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import DNS
        self.assertEqual(self.msg, DNS.from_valid_json(self.jmsg))


class DNSResponseTest(unittest.TestCase):

    def setUp(self):
        from letsencrypt.acme.challenges import DNSResponse
        self.msg = DNSResponse()
        self.jmsg = {'type': 'dns'}

    def test_to_json(self):
        self.assertEqual(self.jmsg, self.msg.to_json())

    def test_from_json(self):
        from letsencrypt.acme.challenges import DNSResponse
        self.assertEqual(self.msg, DNSResponse.from_valid_json(self.jmsg))


if __name__ == '__main__':
    unittest.main()
