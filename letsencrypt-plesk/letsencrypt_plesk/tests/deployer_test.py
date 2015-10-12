"""Test for letsencrypt_plesk.configurator."""
import unittest
import os

from letsencrypt_plesk import deployer
from letsencrypt_plesk.tests import api_mock


class PleskDeployerTest(unittest.TestCase):
    def setUp(self):
        super(PleskDeployerTest, self).setUp()
        self.deployer = deployer.PleskDeployer(
            plesk_api_client=api_mock.PleskApiMock(),
            domain="example.com")

    def test_install_cert(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_install')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_install_ok')
        self.deployer.install_cert(
            cert_path=self._mock_file('-----CERTIFICATE-----'),
            key_path=self._mock_file('-----PRIVATE-----'))
        self.deployer.plesk_api_client.assert_called()

    def _mock_file(self, data):
        tmp_file = os.tmpnam()
        with open(tmp_file, 'w') as f:
            f.write(data)
        return tmp_file

    def test_get_certs(self):
        self.deployer.plesk_api_client.expects_request(
            'request_certificate_get_pool')
        self.deployer.plesk_api_client.will_response(
            'response_certificate_get_pool_many')
        certs = self.deployer.get_certs()
        self.deployer.plesk_api_client.assert_called()
        self.assertEqual(
            certs,
            ['Lets Encrypt example.com', 'My Own Cert'])

    def test_assign_cert(self):
        self.deployer.plesk_api_client.expects_request(
            'request_site_set_certificate')
        self.deployer.plesk_api_client.will_response(
            'response_site_set_ok')
        self.deployer.assign_cert()
        self.deployer.plesk_api_client.assert_called()

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
