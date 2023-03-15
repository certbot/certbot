"""Tests for new style enhancements"""
import sys
import unittest
from unittest import mock

import pytest

from certbot._internal.plugins import null
from certbot.plugins import enhancements
import certbot.tests.util as test_util
from certbot.tests.util import FreezableMock


class EnhancementTest(test_util.ConfigTestCase):
    """Tests for new style enhancements in certbot.plugins.enhancements"""

    def setUp(self) -> None:
        super().setUp()
        self.mockinstaller = mock.MagicMock(spec=enhancements.AutoHSTSEnhancement)


    @test_util.patch_display_util()
    def test_enhancement_enabled_enhancements(self, _: FreezableMock) -> None:
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
        assert len(enabled) == 2
        assert [i for i in enabled if i["name"] == "autohsts"]
        assert [i for i in enabled if i["name"] == "somethingelse"]

    def test_are_requested(self) -> None:
        assert len(list(enhancements.enabled_enhancements(self.config))) == 0
        assert not enhancements.are_requested(self.config)
        self.config.auto_hsts = True
        assert len(list(enhancements.enabled_enhancements(self.config))) == 1
        assert enhancements.are_requested(self.config)

    def test_are_supported(self) -> None:
        self.config.auto_hsts = True
        unsupported = null.Installer(self.config, "null")
        assert enhancements.are_supported(self.config, self.mockinstaller)
        assert not enhancements.are_supported(self.config, unsupported)

    def test_enable(self) -> None:
        self.config.auto_hsts = True
        domains = ["example.com", "www.example.com"]
        lineage = "lineage"
        enhancements.enable(lineage, domains, self.mockinstaller, self.config)
        assert self.mockinstaller.enable_autohsts.called
        assert self.mockinstaller.enable_autohsts.call_args[0] == \
                          (lineage, domains)


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
