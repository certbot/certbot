"""Provides a common base for Apache proxies"""
import logging
import re
import os
import subprocess

import mock

from letsencrypt import configuration
from letsencrypt_apache import configurator
from tests.compatibility import errors
from tests.compatibility import util
from tests.compatibility.configurators import common as configurators_common


APACHE_VERSION_REGEX = re.compile(r"Apache/([0-9\.]*)", re.IGNORECASE)


logger = logging.getLogger(__name__)


class Proxy(configurators_common.Proxy):
    # pylint: disable=too-many-instance-attributes
    """A common base for Apache test configurators"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super(Proxy, self).__init__(args)
        self.le_config.apache_le_vhost_ext = "-le-ssl.conf"

        self._patch = mock.patch('letsencrypt_apache.configurator.subprocess')
        self._mock = self._patch.start()
        self._mock.check_call = self.check_call_in_docker
        self._mock.Popen = self.popen_in_docker

        self.server_root = self.modules = self.version = self.test_conf = None
        self.config_file = self._apache_configurator = self._names = None

    def __getattr__(self, name):
        """Wraps the Apache Configurator methods"""
        method = getattr(self._apache_configurator, name, None)
        if callable(method):
            return method
        else:
            raise AttributeError()

    def load_config(self):
        """Loads the next configuration for the plugin to test"""
        config = self.get_next_config()
        logger.info("Loading configuration: %s", config)
        self._parse_config(config)
        self.preprocess_config()
        self._prepare_configurator()

        try:
            self.check_call_in_docker(
                "apachectl -d {0} -f {1} -k restart".format(
                    self.server_root, self.config_file))
        except errors.Error:
            raise errors.Error(
                "Apache failed to load {0} before tests started".format(
                    config))

    def preprocess_config(self):
        # pylint: disable=anomalous-backslash-in-string
        """Prepares the configuration for use in the Docker"""
        self.test_conf = os.path.join(self.server_root, "test.conf")
        open(self.test_conf, "w").close()
        subprocess.check_call(
            ["sed", "-i", "1iInclude test.conf", self.config_file])
        find = subprocess.Popen(
            ["find", self.server_root, "-type", "f"],
            stdout=subprocess.PIPE)
        subprocess.check_call([
            "xargs", "sed", "-e",
            "s/DocumentRoot.*/DocumentRoot \/usr\/local\/apache2\/htdocs/I",
            "-e",
            "s/SSLPassPhraseDialog.*/SSLPassPhraseDialog builtin/I",
            "-i"], stdin=find.stdout)

    def _parse_config(self, config):
        """Parses extra information in server config directory"""
        self.server_root = _get_server_root(config)
        self.modules = _get_modules(config)
        self.version = _get_version(config)
        self._names = _get_names(config)

        with open(os.path.join(config, "config_file")) as f:
            config_file_base = f.readline().rstrip()

        self.config_file = os.path.join(self.server_root, config_file_base)

    def _prepare_configurator(self):
        """Prepares the Apache plugin for testing"""
        self.le_config.apache_server_root = self.server_root
        self.le_config.apache_ctl = "apachectl -d {0} -f {1}".format(
            self.server_root, self.config_file)
        self.le_config.apache_enmod = "a2enmod.sh"
        self.le_config.apache_init = self.le_config.apache_ctl + " -k"

        self._apache_configurator = configurator.ApacheConfigurator(
            config=configuration.NamespaceConfig(self.le_config),
            name="apache")
        self._apache_configurator.prepare()

    def get_test_domain_names(self):
        """Returns a list of domain names to test against the plugin"""
        if self._names:
            return self._names
        else:
            raise errors.Error("No configuration file loaded")


def _get_server_root(config):
    """Returns the server root directory in config"""
    subdirs = [
        name for name in os.listdir(config)
        if os.path.isdir(os.path.join(config, name))]

    if len(subdirs) != 1:
        errors.Error("Malformed configuration directiory {0}".format(config))

    return os.path.join(config, subdirs[0].rstrip())


def _get_names(config):
    """Returns domains names for config"""
    names = set()
    with open(os.path.join(config, "vhosts")) as f:
        for line in f:
            # If parsing a specific vhost
            if line[0].isspace():
                words = line.split()
                if words[0] == "alias":
                    names.add(words[1])
                # If for port 80 and not IP vhost
                elif words[1] == "80" and not util.IP_REGEX.match(words[3]):
                    names.add(words[3])
            elif "NameVirtualHost" not in line:
                words = line.split()
                if ((words[0].endswith("*") or words[0].endswith("80")) and
                        util.IP_REGEX.match(words[1])):
                    names.add(words[1])

    return names


def _get_modules(config):
    """Returns the list of modules found in module_list"""
    modules = []
    with open(os.path.join(config, "modules")) as f:
        for line in f:
            # Modules list is indented, everything else is headers/footers
            if line[0].isspace():
                words = line.split()
                # Modules redundantly end in "_module" which we can discard
                modules.append(words[0][:-7])

    return modules


def _get_version(config):
    """Return version of Apache Server.

    Version is returned as tuple. (ie. 2.4.7 = (2, 4, 7)). Code taken from
    the Apache plugin.

    """
    with open(os.path.join(config, "version")) as f:
        # Should be on first line of input
        matches = APACHE_VERSION_REGEX.findall(f.readline())

    if len(matches) != 1:
        raise errors.Error("Unable to find Apache version")

    return tuple([int(i) for i in matches[0].split(".")])
