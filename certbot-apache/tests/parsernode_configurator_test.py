"""Tests for ApacheConfigurator for AugeasParserNode classes"""
import unittest
from unittest import mock # type: ignore

import util

try:
    import apacheconfig
    HAS_APACHECONFIG = True
except ImportError:  # pragma: no cover
    HAS_APACHECONFIG = False


@unittest.skipIf(not HAS_APACHECONFIG, reason='Tests require apacheconfig dependency')
class ConfiguratorParserNodeTest(util.ApacheTest):  # pylint: disable=too-many-public-methods
    """Test AugeasParserNode using available test configurations"""

    def setUp(self):  # pylint: disable=arguments-differ
        super().setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir,
            self.work_dir, use_parsernode=True)
        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def test_parsernode_get_vhosts(self):
        self.config.USE_PARSERNODE = True
        vhosts = self.config.get_virtual_hosts()
        # Legacy get_virtual_hosts() do not set the node
        self.assertIsNotNone(vhosts[0].node)

    def test_parsernode_get_vhosts_mismatch(self):
        vhosts = self.config.get_virtual_hosts_v2()
        # One of the returned VirtualHost objects differs
        vhosts[0].name = "IdidntExpectThat"
        self.config.get_virtual_hosts_v2 = mock.MagicMock(return_value=vhosts)
        with self.assertRaises(AssertionError):
            _ = self.config.get_virtual_hosts()


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
