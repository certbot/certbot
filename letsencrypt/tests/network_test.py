"""Tests for letsencrypt.network."""
import shutil
import tempfile
import unittest

import mock

from letsencrypt import account


class NetworkTest(unittest.TestCase):
    """Tests for letsencrypt.network.Network."""

    def setUp(self):
        from letsencrypt.network import Network
        self.net = Network(
            new_reg_uri=None, key=None, alg=None, verify_ssl=None)

        self.config = mock.Mock(accounts_dir=tempfile.mkdtemp())
        self.contact = ('mailto:cert-admin@example.com', 'tel:+12025551212')

    def tearDown(self):
        shutil.rmtree(self.config.accounts_dir)

    def test_register_from_account(self):
        self.net.register = mock.Mock()
        acc = account.Account(
            self.config, 'key', email='cert-admin@example.com',
            phone='+12025551212')

        self.net.register_from_account(acc)

        self.net.register.assert_called_with(contact=self.contact)

    def test_register_from_account_partial_info(self):
        self.net.register = mock.Mock()
        acc = account.Account(
            self.config, 'key', email='cert-admin@example.com')
        acc2 = account.Account(self.config, 'key')

        self.net.register_from_account(acc)
        self.net.register.assert_called_with(
            contact=('mailto:cert-admin@example.com',))

        self.net.register_from_account(acc2)
        self.net.register.assert_called_with(contact=())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
