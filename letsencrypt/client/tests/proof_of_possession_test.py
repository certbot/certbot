"""Tests for proof_of_possession.py"""
import Crypto.PublicKey.RSA
import os
import pkg_resources
import unittest

import mock

from letsencrypt.acme import challenges
from letsencrypt.acme import jose
from letsencrypt.client import achallenges
from letsencrypt.client import proof_of_possession
from letsencrypt.client.display import util as display_util


BASE_PACKAGE = "letsencrypt.client.tests"
CERT0_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "cert.pem"))
CERT1_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "cert-san.pem"))
CERT2_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "matching_cert.pem"))
KEY_PATH = pkg_resources.resource_filename(
    BASE_PACKAGE, os.path.join("testdata", "rsa512_key.pem"))
KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    BASE_PACKAGE, os.path.join('testdata', 'rsa512_key.pem'))).publickey()


class ProofOfPossessionTest(unittest.TestCase):
    def setUp(self):
        self.installer = mock.MagicMock()
        self.installer.get_all_certs_keys.return_value = zip(
            [CERT0_PATH, CERT1_PATH, CERT2_PATH], 3 * [KEY_PATH], 3 * [None])
        self.proof_of_pos = proof_of_possession.ProofOfPossession(
            self.installer)

        hints = challenges.ProofOfPossession.Hints(
            jwk=jose.JWKRSA(key=KEY), cert_fingerprints=(),
            certs=(), serial_numbers=(), subject_key_identifiers=(),
            issuers=(), authorized_for=())
        challenge = challenges.ProofOfPossession(
            alg=jose.RS256, nonce='zczv4HMLVe_0kimJ25Juig', hints=hints)
        self.achall = achallenges.ProofOfPossession(
            challb=challenge, domain="example.com")

    def test_perform_no_input(self):
        response = self.proof_of_pos.perform(self.achall)
        self.assertTrue(response.verify())

    @mock.patch("letsencrypt.client.recovery_token.zope.component.getUtility")
    def test_perform_with_input(self, mock_input):
        # Remove the matching certificate
        self.installer.get_all_certs_keys.return_value.pop()
        mock_input().input.side_effect = [(display_util.CANCEL, ""),
                                          (display_util.OK, CERT0_PATH),
                                          (display_util.OK, KEY_PATH)]

        response = self.proof_of_pos.perform(self.achall)
        self.assertFalse(response)

        response = self.proof_of_pos.perform(self.achall)
        self.assertFalse(response)

        response = self.proof_of_pos.perform(self.achall)
        self.assertTrue(response.verify())

    def test_perform_bad_challenge(self):
        hints = challenges.ProofOfPossession.Hints(
            jwk=jose.jwk.JWKOct(key=KEY), cert_fingerprints=(),
            certs=(), serial_numbers=(), subject_key_identifiers=(),
            issuers=(), authorized_for=())
        challenge = challenges.ProofOfPossession(
            alg=jose.HS512, nonce='zczv4HMLVe_0kimJ25Juig', hints=hints)
        self.achall = achallenges.ProofOfPossession(
            challb=challenge, domain="example.com")

        response = self.proof_of_pos.perform(self.achall)
        self.assertEqual(response, None)
