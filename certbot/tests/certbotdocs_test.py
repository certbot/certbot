"""Tests for help text when invoked with environmental variable CERTBOT_DOCS=1"""
import itertools
import os
import pkg_resources
import unittest

import mock
import six

from certbot import cli, constants
from certbot.plugins import disco

import certbot.tests.util as test_util


class CertbotDocsTest(test_util.ConfigTestCase):
    """Tests for CERTBOT_DOCS=1"""

    @staticmethod
    def _parse(*args, **kwargs):
        """Get result of cli.prepare_and_parse_args."""

        plugins = disco.PluginsRegistry.find_all()
        return cli.prepare_and_parse_args(plugins, *args, **kwargs)

    def _help_output(self):
        "Get output of certbot --help all"

        output = six.StringIO()

        def write_msg(message, *args, **kwargs): # pylint: disable=missing-docstring,unused-argument
            output.write(message)

        with mock.patch('certbot.main.sys.stdout', new=output):
            with test_util.patch_get_utility() as mock_get_utility:
                mock_get_utility().notification.side_effect = write_msg
                with mock.patch('certbot.main.sys.stderr'):
                    self.assertRaises(SystemExit, self._parse, ["help", "all"], output)

        return output.getvalue()

    def test_help_certbot_docs(self):
        """Test that a consistent help text is printed when CERTBOT_DOCS=1
        environmental variable is set."""
        os.environ["CERTBOT_DOCS"] = "1"

        entry_points = itertools.chain(
            pkg_resources.iter_entry_points(
                constants.SETUPTOOLS_PLUGINS_ENTRY_POINT),
            pkg_resources.iter_entry_points(
                constants.OLD_SETUPTOOLS_PLUGINS_ENTRY_POINT),)
        apache_ep = None
        for ep in entry_points:
            if ep.name == "apache":
                apache_ep = disco.PluginEntryPoint(ep)
        mock_add = mock.MagicMock()
        with mock.patch("certbot.util.exe_exists") as mock_exe:
            mock_exe.return_value = True
            apache_plugin = apache_ep.init(config=self.config)
            apache_plugin._prepare_options()
            apache_plugin.add_parser_arguments(mock_add)
            expected_srv_root = {'default': '/etc/apache2',
                                 'help': 'Apache server root directory'}
            found = False
            for c in mock_add.mock_calls:
                if c[2] == expected_srv_root:
                    found = True
            self.assertTrue(found)
            self.assertTrue("Please note that the default values of the Apache" in apache_plugin.description)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
