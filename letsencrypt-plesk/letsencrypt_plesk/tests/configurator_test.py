"""Test for letsencrypt_plesk.configurator."""
import unittest
import mock

from letsencrypt_plesk import configurator
from letsencrypt_plesk import api_client


class PleskConfiguratorTest(unittest.TestCase):
    def setUp(self):
        super(PleskConfiguratorTest, self).setUp()
        self.configurator = configurator.PleskConfigurator(
            config=mock.MagicMock(
                key=None
            ),
            name="plesk"
        )
        self.configurator.plesk_api_client = mock.MagicMock()
        self.configurator.prepare()

    def test_get_all_names(self):
        api_request_mock = self.configurator.plesk_api_client.request
        request = api_client.XmlToDict("""
        <packet>
        <webspace>
          <get>
                 <filter></filter>
                 <dataset><gen_info/></dataset>
          </get>
        </webspace>
        <site>
            <get>
                 <filter></filter>
                 <dataset><gen_info/></dataset>
            </get>
        </site>
        </packet>
        """)
        response = api_client.XmlToDict("""
        <packet version="1.6.7.0">
        <webspace>
            <get>
                <result>
                    <status>ok</status>
                    <filter-id>26</filter-id>
                    <id>26</id>
                    <data>
                        <gen_info>
                            <cr_date>2014-03-19</cr_date>
                            <name>first.example.com</name>
                        </gen_info>
                    </data>
                </result>
                <result>
                    <status>ok</status>
                    <filter-id>53</filter-id>
                    <id>53</id>
                    <data>
                        <gen_info>
                            <cr_date>2014-04-01</cr_date>
                            <name>second.example.com</name>
                        </gen_info>
                    </data>
                </result>
            </get>
        </webspace>
        <site>
            <get>
                <result>
                    <status>ok</status>
                    <filter-id>80</filter-id>
                    <id>80</id>
                    <data>
                        <gen_info>
                            <cr_date>2014-05-13</cr_date>
                            <name>third.example.com</name>
                        </gen_info>
                    </data>
                </result>
            </get>
        </site>
        </packet>
        """)
        api_request_mock.return_value = response
        names = self.configurator.get_all_names()
        api_request_mock.assert_called_once_with(request.native())
        self.assertEqual(
            names,
            ['first.example.com', 'second.example.com', 'third.example.com'])

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
