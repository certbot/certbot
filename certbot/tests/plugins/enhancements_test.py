"""Tests for new style enhancements"""
import unittest

import mock

from certbot._internal.plugins import null
from certbot.plugins import enhancements
import certbot.tests.util as test_util


class EnhancementTest(test_util.ConfigTestCase):
    """Tests for new style enhancements in certbot.plugins.enhancements"""

    def setUp(self):
        super(EnhancementTest, self).setUp()
        self.mockinstaller = mock.MagicMock(spec=enhancements.AutoHSTSEnhancement)


    @test_util.patch_get_utility()
    def test_enhancement_enabled_enhancements(self, _):
        FAKEINDEX = [
            {
                "name": "autohsts",
                "cli_dest": "auto_hsts",
            },
            {
                "name": "somethingelse",
                "cli_dest": "something",
            }
        ]
        with mock.patch("certbot.plugins.enhancements._INDEX", FAKEINDEX):
            self.config.auto_hsts = True
            self.config.something = True
            enabled = list(enhancements.enabled_enhancements(self.config))
        self.assertEqual(len(enabled), 2)
        self.assertTrue([i for i in enabled if i["name"] == "autohsts"])
        self.assertTrue([i for i in enabled if i["name"] == "somethingelse"])

    def test_are_requested(self):
        self.assertEqual(len(list(enhancements.enabled_enhancements(self.config))), 0)
        self.assertFalse(enhancements.are_requested(self.config))
        self.config.auto_hsts = True
        self.assertEqual(len(list(enhancements.enabled_enhancements(self.config))), 1)
        self.assertTrue(enhancements.are_requested(self.config))

    def test_are_supported(self):
        self.config.auto_hsts = True
        unsupported = null.Installer(self.config, "null")
        self.assertTrue(enhancements.are_supported(self.config, self.mockinstaller))
        self.assertFalse(enhancements.are_supported(self.config, unsupported))

    def test_enable(self):
        self.config.auto_hsts = True
        domains = ["example.com", "www.example.com"]
        lineage = "lineage"
        enhancements.enable(lineage, domains, self.mockinstaller, self.config)
        self.assertTrue(self.mockinstaller.enable_autohsts.called)
        self.assertEqual(self.mockinstaller.enable_autohsts.call_args[0],
                          (lineage, domains))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
