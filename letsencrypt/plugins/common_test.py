"""Tests for letsencrypt.plugins.common."""
import unittest

import mock


class NamespaceFunctionsTest(unittest.TestCase):
    """Tests for letsencrypt.plugins.common.*_namespace functions."""

    def test_option_namespace(self):
        from letsencrypt.plugins.common import option_namespace
        self.assertEqual("foo-", option_namespace("foo"))

    def test_dest_namespace(self):
        from letsencrypt.plugins.common import dest_namespace
        self.assertEqual("foo_", dest_namespace("foo"))


class PluginTest(unittest.TestCase):
    """Test for letsencrypt.plugins.common.Plugin."""

    def setUp(self):
        from letsencrypt.plugins.common import Plugin

        class MockPlugin(Plugin):  # pylint: disable=missing-docstring
            @classmethod
            def add_parser_arguments(cls, add):
                add("foo-bar", dest="different_to_foo_bar", x=1, y=None)

        self.plugin_cls = MockPlugin
        self.config = mock.MagicMock()
        self.plugin = MockPlugin(config=self.config, name="mock")

    def test_init(self):
        self.assertEqual("mock", self.plugin.name)
        self.assertEqual(self.config, self.plugin.config)

    def test_option_namespace(self):
        self.assertEqual("mock-", self.plugin.option_namespace)

    def test_dest_namespace(self):
        self.assertEqual("mock_", self.plugin.dest_namespace)

    def test_dest(self):
        self.assertEqual("mock_foo_bar", self.plugin.dest("foo-bar"))
        self.assertEqual("mock_foo_bar", self.plugin.dest("foo_bar"))

    def test_conf(self):
        self.assertEqual(self.config.mock_foo_bar, self.plugin.conf("foo-bar"))

    def test_inject_parser_options(self):
        parser = mock.MagicMock()
        self.plugin_cls.inject_parser_options(parser, "mock")
        # note that inject_parser_options doesn't check if dest has
        # correct prefix
        parser.add_argument.assert_called_once_with(
            "--mock-foo-bar", dest="different_to_foo_bar", x=1, y=None)


if __name__ == "__main__":
    unittest.main()
