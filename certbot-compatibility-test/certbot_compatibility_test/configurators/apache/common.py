"""Provides a common base for Apache proxies"""
import re
import os
import shutil
import subprocess

import mock
import zope.interface

from certbot import configuration
from certbot import errors as le_errors
from certbot_apache import configurator
from certbot_apache import constants
from certbot_compatibility_test import errors
from certbot_compatibility_test import interfaces
from certbot_compatibility_test import util
from certbot_compatibility_test.configurators import common as configurators_common


APACHE_VERSION_REGEX = re.compile(r"Apache/([0-9\.]*)", re.IGNORECASE)
APACHE_COMMANDS = ["apachectl", "a2enmod", "a2dismod"]


@zope.interface.implementer(interfaces.IConfiguratorProxy)
class Proxy(configurators_common.Proxy):
    # pylint: disable=too-many-instance-attributes
    """A common base for Apache test configurators"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super(Proxy, self).__init__(args)
        self.le_config.apache_le_vhost_ext = "-le-ssl.conf"

        self.modules = self.server_root = self.test_conf = self.version = None
        self._apache_configurator = self._all_names = self._test_names = None
        patch = mock.patch(
            "certbot_apache.configurator.display_ops.select_vhost")
        mock_display = patch.start()
        mock_display.side_effect = le_errors.PluginError(
            "Unable to determine vhost")

    def __getattr__(self, name):
        """Wraps the Apache Configurator methods"""
        method = getattr(self._apache_configurator, name, None)
        if callable(method):
            return method
        else:
            raise AttributeError()

    def load_config(self):
        """Loads the next configuration for the plugin to test"""

        config = super(Proxy, self).load_config()
        self._all_names, self._test_names = _get_names(config)

        server_root = _get_server_root(config)
        # with open(os.path.join(config, "config_file")) as f:
        #    config_file = os.path.join(server_root, f.readline().rstrip())
        shutil.rmtree("/etc/apache2")
        shutil.copytree(server_root, "/etc/apache2", symlinks=True)

        self._prepare_configurator()

        try:
            subprocess.check_call("apachectl -k start".split())
        except errors.Error:
            raise errors.Error(
                "Apache failed to load {0} before tests started".format(
                    config))

        return config

    def _prepare_configurator(self):
        """Prepares the Apache plugin for testing"""
        for k in constants.CLI_DEFAULTS_DEBIAN.keys():
            setattr(self.le_config, "apache_" + k, constants.os_constant(k))

        # An alias
        self.le_config.apache_handle_modules = self.le_config.apache_handle_mods

        self._apache_configurator = configurator.ApacheConfigurator(
            config=configuration.NamespaceConfig(self.le_config),
            name="apache")
        self._apache_configurator.prepare()

    def cleanup_from_tests(self):
        """Performs any necessary cleanup from running plugin tests"""
        super(Proxy, self).cleanup_from_tests()
        mock.patch.stopall()

    def get_all_names_answer(self):
        """Returns the set of domain names that the plugin should find"""
        if self._all_names:
            return self._all_names
        else:
            raise errors.Error("No configuration file loaded")

    def get_testable_domain_names(self):
        """Returns the set of domain names that can be tested against"""
        if self._test_names:
            return self._test_names
        else:
            return {"example.com"}

    def deploy_cert(self, domain, cert_path, key_path, chain_path=None,
                    fullchain_path=None):
        """Installs cert"""
        cert_path, key_path, chain_path = self.copy_certs_and_keys(
            cert_path, key_path, chain_path)
        self._apache_configurator.deploy_cert(
            domain, cert_path, key_path, chain_path, fullchain_path)


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
    return all_names, non_ip_names
