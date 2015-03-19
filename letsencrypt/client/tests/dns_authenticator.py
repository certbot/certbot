"""Tests for letsencrypt.client.dns_authenticator."""
import unittest

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import errors

class PerformTest(unittest.TestCase):
	"""Test DNS perform function."""

	def setUp(self):
		from letsencrypt.dns_authenticator import DNSAuthenticator

		self.auth = DNSAuthenticator(mock.MagicMock(
			dns_server="localhost",
			dns_server_port=53,
			dns_tsig_keys=[
				["example.key",
				"+Cdjlkef9ZTSeixERZ433Q==",
				["example.com"]]
			]
		))

	def test_chall_pref(self):
		self.assertEqual(
			self.auth.get_chall_pref("example.com"), [challenges.DNS])


if __name__ == '__main__':
    unittest.main()
