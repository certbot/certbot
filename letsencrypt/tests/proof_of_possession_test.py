"""Tests for letsencrypt.proof_of_possession."""
import Crypto.PublicKey.RSA
import os
import pkg_resources
import unittest

import mock

from acme import challenges
from acme import jose
from acme import messages2

from letsencrypt import achallenges
from letsencrypt import proof_of_possession
from letsencrypt.display import util as display_util


BASE_PACKAGE = "letsencrypt.tests"
CERT0_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "cert.pem"))
CERT1_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "cert-san.pem"))
CERT2_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "dsa_cert.pem"))
CERT2_KEY_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "dsa512_key.pem"))
CERT3_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "matching_cert.pem"))
CERT3_KEY_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "rsa512_key.pem"))
CERT3_KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    BASE_PACKAGE, os.path.join('testdata', 'rsa512_key.pem'))).publickey()


class ProofOfPossessionTest(unittest.TestCase):
    def setUp(self):
        self.installer = mock.MagicMock()
        certs = [CERT0_PATH, CERT1_PATH, CERT2_PATH, CERT3_PATH]
        keys = [None, None, CERT2_KEY_PATH, CERT3_KEY_PATH]
        self.installer.get_all_certs_keys.return_value = zip(
            certs, keys, 4 * [None])
        self.proof_of_pos = proof_of_possession.ProofOfPossession(
            self.installer)

        hints = challenges.ProofOfPossession.Hints(
            jwk=jose.JWKRSA(key=CERT3_KEY), cert_fingerprints=(),
            certs=(), serial_numbers=(), subject_key_identifiers=(),
            issuers=(), authorized_for=())
        chall = challenges.ProofOfPossession(
            alg=jose.RS256, nonce='zczv4HMLVe_0kimJ25Juig', hints=hints)
        challb = messages2.ChallengeBody(
            chall=chall, uri="http://example", status=messages2.STATUS_PENDING)
        self.achall = achallenges.ProofOfPossession(
            challb=challb, domain="example.com")

    def test_perform_bad_challenge(self):
        hints = challenges.ProofOfPossession.Hints(
            jwk=jose.jwk.JWKOct(key=CERT3_KEY), cert_fingerprints=(),
            certs=(), serial_numbers=(), subject_key_identifiers=(),
            issuers=(), authorized_for=())
        chall = challenges.ProofOfPossession(
            alg=jose.HS512, nonce='zczv4HMLVe_0kimJ25Juig', hints=hints)
        challb = messages2.ChallengeBody(
            chall=chall, uri="http://example", status=messages2.STATUS_PENDING)
        self.achall = achallenges.ProofOfPossession(
            challb=challb, domain="example.com")
        self.assertEqual(self.proof_of_pos.perform(self.achall), None)

    def test_perform_no_input(self):
        self.assertTrue(self.proof_of_pos.perform(self.achall).verify())

    @mock.patch("letsencrypt.recovery_token.zope.component.getUtility")
    def test_perform_with_input(self, mock_input):
        # Remove the matching certificate
        self.installer.get_all_certs_keys.return_value.pop()
        mock_input().input.side_effect = [(display_util.CANCEL, ""),
                                          (display_util.OK, CERT0_PATH),
                                          (display_util.OK, "imaginary_file"),
                                          (display_util.OK, CERT3_KEY_PATH)]
        self.assertFalse(self.proof_of_pos.perform(self.achall))
        self.assertFalse(self.proof_of_pos.perform(self.achall))
        self.assertFalse(self.proof_of_pos.perform(self.achall))
        self.assertTrue(self.proof_of_pos.perform(self.achall).verify())


if __name__ == "__main__":
    unittest.main() # pragma: no cover
