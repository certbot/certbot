"""Test for letsencrypt_plesk.configurator."""
import unittest
import mock
import os

from letsencrypt_plesk import deployer
from letsencrypt_plesk import api_client


class PleskConfiguratorTest(unittest.TestCase):
    def setUp(self):
        super(PleskConfiguratorTest, self).setUp()
        self.deployer = deployer.PleskDeployer(
            plesk_api_client=mock.MagicMock(),
            domain="example.com"
        )

    def test_install_cert(self):
        api_request_mock = self.deployer.plesk_api_client.request
        request = api_client.XmlToDict("""
        <packet>
        <certificate>
            <install>
                <name>Lets Encrypt example.com</name>
                <site>example.com</site>
                <content>
                    <csr/>
                    <pvt>-----PRIVATE-----</pvt>
                    <cert>-----CERTIFICATE-----</cert>
                    <ca/>
                    </content>
                </install>
            </certificate>
        </packet>
        """, force_array=True)
        response = api_client.XmlToDict("""
        <packet version="1.6.7.0">
            <certificate>
                <install>
                    <result>
                        <status>ok</status>
                    </result>
                </install>
            </certificate>
        </packet>
        """)
        api_request_mock.return_value = response
        self.deployer.install_cert(
            cert_path=self._mock_file('-----CERTIFICATE-----'),
            key_path=self._mock_file('-----PRIVATE-----'))
        api_request_mock.assert_called_once_with(request)

    def _mock_file(self, data):
        tmp_file = os.tmpnam()
        with open(tmp_file, 'w') as f:
            f.write(data)
        return tmp_file

    def test_get_certs(self):
        api_request_mock = self.deployer.plesk_api_client.request
        request = api_client.XmlToDict("""
        <packet>
        <certificate>
            <get-pool>
                <filter>
                    <domain-name>example.com</domain-name>
                </filter>
            </get-pool>
            </certificate>
        </packet>
        """, force_array=True)
        response = api_client.XmlToDict("""
        <packet version="1.6.7.0">
            <certificate>
                <get-pool>
                    <result>
                        <status>ok</status>
                        <filter-id>example.com</filter-id>
                        <id>1</id>
                        <certificates>
                            <certificate>
                                <name>Lets Encrypt example.com</name>
                            </certificate>
                            <certificate>
                                <name>My Own Cert</name>
                            </certificate>
                        </certificates>
                    </result>
                </get-pool>
            </certificate>
        </packet>
        """)
        api_request_mock.return_value = response
        certs = self.deployer.get_certs()
        api_request_mock.assert_called_once_with(request)
        self.assertEqual(
            certs,
            ['Lets Encrypt example.com', 'My Own Cert'])

    def test_assign_cert(self):
        api_request_mock = self.deployer.plesk_api_client.request
        request = api_client.XmlToDict("""
        <packet>
            <site>
                <set>
                    <filter>
                        <name>example.com</name>
                    </filter>
                    <values>
                        <hosting>
                            <vrt_hst>
                                <property>
                                    <name>ssl</name>
                                    <value>true</value>
                                </property>
                                <property>
                                    <name>certificate_name</name>
                                    <value>Lets Encrypt example.com</value>
                                </property>
                            </vrt_hst>
                        </hosting>
                    </values>
                </set>
            </site>
        </packet>
        """, force_array=True)
        response = api_client.XmlToDict("""
        <packet version="1.6.7.0">
            <site>
                <set>
                    <result>
                        <status>ok</status>
                        <filter-id>example.com</filter-id>
                        <id>1</id>
                    </result>
                </set>
            </site>
        </packet>
        """)
        api_request_mock.return_value = response
        self.deployer.assign_cert()
        api_request_mock.assert_called_once_with(request)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
