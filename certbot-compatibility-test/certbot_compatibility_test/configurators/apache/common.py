"""Provides a common base for Apache proxies"""
import os
import shutil
import subprocess

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
import zope.interface

from certbot import errors as le_errors
from certbot import util as certbot_util
from certbot._internal import configuration
from certbot_apache._internal import entrypoint
from certbot_compatibility_test import errors
from certbot_compatibility_test import interfaces
from certbot_compatibility_test import util
from certbot_compatibility_test.configurators import common as configurators_common


@zope.interface.implementer(interfaces.IConfiguratorProxy)
class Proxy(configurators_common.Proxy):
    """A common base for Apache test configurators"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super(Proxy, self).__init__(args)
        self.le_config.apache_le_vhost_ext = "-le-ssl.conf"

        self.modules = self.server_root = self.test_conf = self.version = None
        patch = mock.patch(
            "certbot_apache._internal.configurator.display_ops.select_vhost")
        mock_display = patch.start()
        mock_display.side_effect = le_errors.PluginError(
            "Unable to determine vhost")

    def load_config(self):
        """Loads the next configuration for the plugin to test"""
        config = super(Proxy, self).load_config()
        self._all_names, self._test_names = _get_names(config)

        server_root = _get_server_root(config)
        shutil.rmtree("/etc/apache2")
        shutil.copytree(server_root, "/etc/apache2", symlinks=True)

        self._prepare_configurator()

        try:
            subprocess.check_call("apachectl -k restart".split())
        except errors.Error:
            raise errors.Error(
                "Apache failed to load {0} before tests started".format(
                    config))

        return config

    def _prepare_configurator(self):
        """Prepares the Apache plugin for testing"""
        for k in entrypoint.ENTRYPOINT.OS_DEFAULTS:
            setattr(self.le_config, "apache_" + k,
                    entrypoint.ENTRYPOINT.OS_DEFAULTS[k])

        self._configurator = entrypoint.ENTRYPOINT(
            config=configuration.NamespaceConfig(self.le_config),
            name="apache")
        self._configurator.prepare()

    def cleanup_from_tests(self):
        """Performs any necessary cleanup from running plugin tests"""
        super(Proxy, self).cleanup_from_tests()
        mock.patch.stopall()


def _get_server_root(config):
    """Returns the server root directory in config"""
    subdirs = [
        name for name in os.listdir(config)
        if os.path.isdir(os.path.join(config, name))]

    if len(subdirs) != 1:
        errors.Error("Malformed configuration directory {0}".format(config))

    return os.path.join(config, subdirs[0].rstrip())


def _get_names(config):
    """Returns all and testable domain names in config"""
    all_names = set()
    non_ip_names = set()
    with open(os.path.join(config, "vhosts")) as f:
        for line in f:
            # If parsing a specific vhost
            if line[0].isspace():
                words = line.split()
                if words[0] == "alias":
                    all_names.add(words[1])
                    non_ip_names.add(words[1])
                # If for port 80 and not IP vhost
                elif words[1] == "80" and not util.IP_REGEX.match(words[3]):
                    all_names.add(words[3])
                    non_ip_names.add(words[3])
            elif "NameVirtualHost" not in line:
                words = line.split()
                if (words[0].endswith("*") or words[0].endswith("80") and
                        not util.IP_REGEX.match(words[1]) and
                        words[1].find(".") != -1):
                    all_names.add(words[1])
    return (
        certbot_util.get_filtered_names(all_names),
        certbot_util.get_filtered_names(non_ip_names)
    )
