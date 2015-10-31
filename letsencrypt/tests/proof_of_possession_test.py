"""Tests for letsencrypt.proof_of_possession."""
import os
import tempfile
import unittest

import mock

from acme import challenges
from acme import jose
from acme import messages

from letsencrypt import achallenges
from letsencrypt import proof_of_possession
from letsencrypt.display import util as display_util

from letsencrypt.tests import test_util


CERT0_PATH = test_util.vector_path("cert.der")
CERT2_PATH = test_util.vector_path("dsa_cert.pem")
CERT2_KEY_PATH = test_util.vector_path("dsa512_key.pem")
CERT3_PATH = test_util.vector_path("matching_cert.pem")
CERT3_KEY_PATH = test_util.vector_path("rsa512_key_2.pem")
CERT3_KEY = test_util.load_rsa_private_key("rsa512_key_2.pem").public_key()


class ProofOfPossessionTest(unittest.TestCase):
    def setUp(self):
        self.installer = mock.MagicMock()
        self.cert1_path = tempfile.mkstemp()[1]
        certs = [CERT0_PATH, self.cert1_path, CERT2_PATH, CERT3_PATH]
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
        challb = messages.ChallengeBody(
            chall=chall, uri="http://example", status=messages.STATUS_PENDING)
        self.achall = achallenges.ProofOfPossession(
            challb=challb, domain="example.com")

    def tearDown(self):
        os.remove(self.cert1_path)

    def test_perform_bad_challenge(self):
        hints = challenges.ProofOfPossession.Hints(
            jwk=jose.jwk.JWKOct(key="foo"), cert_fingerprints=(),
            certs=(), serial_numbers=(), subject_key_identifiers=(),
            issuers=(), authorized_for=())
        chall = challenges.ProofOfPossession(
            alg=jose.HS512, nonce='zczv4HMLVe_0kimJ25Juig', hints=hints)
        challb = messages.ChallengeBody(
            chall=chall, uri="http://example", status=messages.STATUS_PENDING)
        self.achall = achallenges.ProofOfPossession(
            challb=challb, domain="example.com")
        self.assertEqual(self.proof_of_pos.perform(self.achall), None)

    def test_perform_no_input(self):
        self.assertTrue(self.proof_of_pos.perform(self.achall).verify())

    @mock.patch("letsencrypt.proof_of_possession.zope.component.getUtility")
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
    unittest.main()  # pragma: no cover
