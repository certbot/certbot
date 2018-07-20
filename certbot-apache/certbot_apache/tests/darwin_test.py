"""Tests for certbot_apache.configurator for Darwin overrides"""
import unittest

from certbot_apache.tests import util

class DarwinTest(util.ApacheTest):
    """Test for Darwin overrides"""

    def setUp(self):  # pylint: disable=arguments-differ
        super(DarwinTest, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir,
            os_info="darwin")

    def test_prepare_options(self):
        self.assertEqual(self.config.option("apache_cmd"),
                         self.config.option("bin"))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
