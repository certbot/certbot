"""Test for letsencrypt_plesk.deployer."""
import unittest
import pkg_resources
import os
import mock

from letsencrypt import errors
from letsencrypt_plesk import deployer
from letsencrypt_plesk.tests import api_mock


class PleskDeployerTest(unittest.TestCase):
    def setUp(self):
        super(PleskDeployerTest, self).setUp()
        self.deployer = deployer.PleskDeployer(
            plesk_api_client=api_mock.PleskApiMock(),
            domain="example.com")
        with open(self._mock_file('test.crt')) as cert_file:
            with open(self._mock_file('test.key')) as key_file:
                self.deployer.init_cert(cert_data=cert_file.read(),
                                        key_data=key_file.read())

    def test_install_cert(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_install')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_install_ok')
        self.deployer.install_cert()
        self.deployer.plesk_api_client.assert_called()

    def test_install_cert_error(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_install')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_install_error')
        self.assertRaises(errors.PluginError, self.deployer.install_cert)
        self.deployer.plesk_api_client.assert_called()

    @staticmethod
    def _mock_file(name):
        return pkg_resources.resource_filename(
            "letsencrypt_plesk.tests", os.path.join("testdata", name))

    def test_get_certs_none(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_get_pool')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_get_pool_none')
        certs = self.deployer.get_certs()
        self.deployer.plesk_api_client.assert_called()
        self.assertEqual(certs, [])

    def test_get_certs_one(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_get_pool')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_get_pool_one')
        certs = self.deployer.get_certs()
        self.deployer.plesk_api_client.assert_called()
        self.assertEqual(certs, ['example-certificate'])

    def test_get_certs_many(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_get_pool')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_get_pool_many')
        certs = self.deployer.get_certs()
        self.deployer.plesk_api_client.assert_called()
        self.assertEqual(certs, [
            'first-certificate', 'second-certificate'])

    def test_assign_cert(self):
        self.deployer.plesk_api_client.expects_request(
            'request_site_set_certificate')
        self.deployer.plesk_api_client.will_response(
            'response_site_set_certificate_ok')
        self.deployer.assign_cert()
        self.deployer.plesk_api_client.assert_called()

    def test_assign_cert_error(self):
        self.deployer.plesk_api_client.expects_request(
            'request_site_set_certificate')
        self.deployer.plesk_api_client.will_response(
            'response_site_set_certificate_error')
        self.assertRaises(errors.PluginError, self.deployer.assign_cert)
        self.deployer.plesk_api_client.assert_called()

    def test_remove_cert(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_remove')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_remove_ok')
        self.deployer.remove_cert()
        self.deployer.plesk_api_client.assert_called()

    def test_remove_cert_error(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_remove')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_remove_error')
        self.assertRaises(errors.PluginError, self.deployer.remove_cert)
        self.deployer.plesk_api_client.assert_called()

    def test_revert(self):
        self.deployer.cert_installed = True
        self.deployer.cert_assigned = True
        self.deployer.remove_cert = mock.MagicMock()
        self.deployer.revert()
        self.deployer.remove_cert.assert_called_once_with()
        self.assertFalse(self.deployer.cert_installed)
        self.assertFalse(self.deployer.cert_assigned)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
