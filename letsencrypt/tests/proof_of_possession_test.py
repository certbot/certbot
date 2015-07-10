"""Tests for letsencrypt.proof_of_possession."""
import os
import pkg_resources
import tempfile
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import mock

from acme import challenges
from acme import jose
from acme import messages

from letsencrypt import achallenges
from letsencrypt import proof_of_possession
from letsencrypt.display import util as display_util


BASE_PACKAGE = "letsencrypt.tests"
CERT0_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "cert.der"))
CERT2_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "dsa_cert.pem"))
CERT2_KEY_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "dsa512_key.pem"))
CERT3_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "matching_cert.pem"))
CERT3_KEY_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "rsa512_key_2.pem"))
with open(CERT3_KEY_PATH) as cert3_file:
    CERT3_KEY = serialization.load_pem_private_key(
        cert3_file.read(), password=None,
        backend=default_backend()).public_key()


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
    unittest.main() # pragma: no cover
