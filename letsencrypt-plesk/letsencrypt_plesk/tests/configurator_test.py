"""Test for letsencrypt_plesk.configurator."""
import unittest
import mock

from letsencrypt_plesk import configurator


class PleskConfiguratorTest(unittest.TestCase):
    def setUp(self):
        super(PleskConfiguratorTest, self).setUp()
        self.configurator = configurator.PleskConfigurator(
            config=mock.MagicMock(
                key=None
            ),
            name="plesk"
        )
        self.configurator.prepare()

    def test_get_all_names(self):
        names = self.configurator.get_all_names()
        print names

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
