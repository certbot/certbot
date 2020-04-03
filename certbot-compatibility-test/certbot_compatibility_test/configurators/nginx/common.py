"""Provides a common base for Nginx proxies"""
import os
import shutil
import subprocess

import zope.interface

from acme.magic_typing import Set
from certbot._internal import configuration
from certbot_compatibility_test import errors
from certbot_compatibility_test import interfaces
from certbot_compatibility_test import util
from certbot_compatibility_test.configurators import common as configurators_common
from certbot_nginx._internal import configurator
from certbot_nginx._internal import constants


@zope.interface.implementer(interfaces.IConfiguratorProxy)
class Proxy(configurators_common.Proxy):
    """A common base for Nginx test configurators"""

    def load_config(self):
        """Loads the next configuration for the plugin to test"""
        config = super(Proxy, self).load_config()
        self._all_names, self._test_names = _get_names(config)

        server_root = _get_server_root(config)

        # XXX: Deleting all of this is kind of scary unless the test
        #      instances really each have a complete configuration!
        shutil.rmtree("/etc/nginx")
        shutil.copytree(server_root, "/etc/nginx", symlinks=True)

        self._prepare_configurator()

        try:
            subprocess.check_call("service nginx reload".split())
        except errors.Error:
            raise errors.Error(
                "Nginx failed to load {0} before tests started".format(
                    config))

        return config

    def _prepare_configurator(self):
        """Prepares the Nginx plugin for testing"""
        for k in constants.CLI_DEFAULTS:
            setattr(self.le_config, "nginx_" + k, constants.os_constant(k))

        conf = configuration.NamespaceConfig(self.le_config)
        zope.component.provideUtility(conf)
        self._configurator = configurator.NginxConfigurator(
            config=conf, name="nginx")
        self._configurator.prepare()


def _get_server_root(config):
    """Returns the server root directory in config"""
    subdirs = [
        name for name in os.listdir(config)
        if os.path.isdir(os.path.join(config, name))]

    if len(subdirs) != 1:
        raise errors.Error("Malformed configuration directory {0}".format(config))

    return os.path.join(config, subdirs[0].rstrip())


def _get_names(config):
    """Returns all and testable domain names in config"""
    all_names = set()  # type: Set[str]
    for root, _dirs, files in os.walk(config):
        for this_file in files:
            update_names = _get_server_names(root, this_file)
            all_names.update(update_names)
    non_ip_names = set(n for n in all_names if not util.IP_REGEX.match(n))
    return all_names, non_ip_names


def _get_server_names(root, filename):
    """Returns all names in a config file path"""
    all_names = set()
    for line in open(os.path.join(root, filename)):
        if line.strip().startswith("server_name"):
            names = line.partition("server_name")[2].rpartition(";")[0]
            for n in names.split():
                # Filter out wildcards in both all_names and test_names
                if not n.startswith("*."):
                    all_names.add(n)
    return all_names
