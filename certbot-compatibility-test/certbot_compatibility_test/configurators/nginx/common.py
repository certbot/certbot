"""Provides a common base for Nginx proxies"""
import os
import shutil
import subprocess

import zope.interface

from certbot import configuration
from certbot_nginx import configurator
from certbot_nginx import constants
from certbot_compatibility_test import errors
from certbot_compatibility_test import interfaces
from certbot_compatibility_test import util
from certbot_compatibility_test.configurators import common as configurators_common


@zope.interface.implementer(interfaces.IConfiguratorProxy)
class Proxy(configurators_common.Proxy):
    # pylint: disable=too-many-instance-attributes
    """A common base for Nginx test configurators"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super(Proxy, self).__init__(args)

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
        for k in constants.CLI_DEFAULTS.keys():
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
    all_names = set()
    for root, _dirs, files in os.walk(config):
        for this_file in files:
            for line in open(os.path.join(root, this_file)):
                if line.strip().startswith("server_name"):
                    names = line.partition("server_name")[2].rpartition(";")[0]
                    for n in names.split():
                        all_names.add(n)
    non_ip_names = set(n for n in all_names if not util.IP_REGEX.match(n))
    return all_names, non_ip_names
