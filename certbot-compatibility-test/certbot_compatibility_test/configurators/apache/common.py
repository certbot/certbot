"""Provides a common base for Apache proxies"""
import re
import os
import subprocess

import mock
import zope.interface

from certbot import configuration
from certbot import errors as le_errors
from certbot_apache import configurator
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

        self._setup_mock()

        self.modules = self.server_root = self.test_conf = self.version = None
        self._apache_configurator = self._all_names = self._test_names = None

    def _setup_mock(self):
        """Replaces specific modules with mock.MagicMock"""
        mock_subprocess = mock.MagicMock()
        mock_subprocess.check_call = self.check_call
        mock_subprocess.Popen = self.popen

        mock.patch(
            "certbot_apache.configurator.subprocess",
            mock_subprocess).start()
        mock.patch(
            "certbot_apache.parser.subprocess",
            mock_subprocess).start()
        mock.patch(
            "certbot.util.subprocess",
            mock_subprocess).start()
        mock.patch(
            "certbot_apache.configurator.util.exe_exists",
            _is_apache_command).start()

        patch = mock.patch(
            "certbot_apache.configurator.display_ops.select_vhost")
        mock_display = patch.start()
        mock_display.side_effect = le_errors.PluginError(
            "Unable to determine vhost")

    def check_call(self, command, *args, **kwargs):
        """If command is an Apache command, command is executed in the
        running docker image. Otherwise, subprocess.check_call is used.

        """
        if _is_apache_command(command):
            command = _modify_command(command)
            return super(Proxy, self).check_call(command, *args, **kwargs)
        else:
            return subprocess.check_call(command, *args, **kwargs)

    def popen(self, command, *args, **kwargs):
        """If command is an Apache command, command is executed in the
        running docker image. Otherwise, subprocess.Popen is used.

        """
        if _is_apache_command(command):
            command = _modify_command(command)
            return super(Proxy, self).popen(command, *args, **kwargs)
        else:
            return subprocess.Popen(command, *args, **kwargs)

    def __getattr__(self, name):
        """Wraps the Apache Configurator methods"""
        method = getattr(self._apache_configurator, name, None)
        if callable(method):
            return method
        else:
            raise AttributeError()

    def load_config(self):
        """Loads the next configuration for the plugin to test"""
        if hasattr(self.le_config, "apache_init_script"):
            try:
                self.check_call([self.le_config.apache_init_script, "stop"])
            except errors.Error:
                raise errors.Error(
                    "Failed to stop previous apache config from running")

        config = super(Proxy, self).load_config()
        self.modules = _get_modules(config)
        self.version = _get_version(config)
        self._all_names, self._test_names = _get_names(config)

        server_root = _get_server_root(config)
        with open(os.path.join(config, "config_file")) as f:
            config_file = os.path.join(server_root, f.readline().rstrip())
        self.test_conf = _create_test_conf(server_root, config_file)

        self.preprocess_config(server_root)
        self._prepare_configurator(server_root, config_file)

        try:
            self.check_call("apachectl -d {0} -f {1} -k start".format(
                server_root, config_file))
        except errors.Error:
            raise errors.Error(
                "Apache failed to load {0} before tests started".format(
                    config))

        return config

    def preprocess_config(self, server_root):
        # pylint: disable=anomalous-backslash-in-string, no-self-use
        """Prepares the configuration for use in the Docker"""

        find = subprocess.Popen(
            ["find", server_root, "-type", "f"],
            stdout=subprocess.PIPE)
        subprocess.check_call([
            "xargs", "sed", "-e", "s/DocumentRoot.*/DocumentRoot "
            "\/usr\/local\/apache2\/htdocs/I",
            "-e", "s/SSLPassPhraseDialog.*/SSLPassPhraseDialog builtin/I",
            "-e", "s/TypesConfig.*/TypesConfig "
            "\/usr\/local\/apache2\/conf\/mime.types/I",
            "-e", "s/LoadModule/#LoadModule/I",
            "-e", "s/SSLCertificateFile.*/SSLCertificateFile "
            "\/usr\/local\/apache2\/conf\/empty_cert.pem/I",
            "-e", "s/SSLCertificateKeyFile.*/SSLCertificateKeyFile "
            "\/usr\/local\/apache2\/conf\/rsa1024_key2.pem/I",
            "-i"], stdin=find.stdout)

    def _prepare_configurator(self, server_root, config_file):
        """Prepares the Apache plugin for testing"""
        self.le_config.apache_server_root = server_root
        self.le_config.apache_ctl = "apachectl -d {0} -f {1}".format(
            server_root, config_file)
        self.le_config.apache_enmod = "a2enmod.sh {0}".format(server_root)
        self.le_config.apache_dismod = "a2dismod.sh {0}".format(server_root)
        self.le_config.apache_init_script = self.le_config.apache_ctl + " -k"

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


def _is_apache_command(command):
    """Returns true if command is an Apache command"""
    if isinstance(command, list):
        command = command[0]

    for apache_command in APACHE_COMMANDS:
        if command.startswith(apache_command):
            return True

    return False


def _modify_command(command):
    """Modifies command so configtest works inside the docker image"""
    if isinstance(command, list):
        for i in xrange(len(command)):
            if command[i] == "configtest":
                command[i] = "-t"
    else:
        command = command.replace("configtest", "-t")

    return command


def _create_test_conf(server_root, apache_config):
    """Creates a test config file and adds it to the Apache config"""
    test_conf = os.path.join(server_root, "test.conf")
    open(test_conf, "w").close()
    subprocess.check_call(
        ["sed", "-i", "1iInclude test.conf", apache_config])
    return test_conf


def _get_server_root(config):
    """Returns the server root directory in config"""
    subdirs = [
        name for name in os.listdir(config)
        if os.path.isdir(os.path.join(config, name))]

    if len(subdirs) != 1:
        errors.Error("Malformed configuration directiory {0}".format(config))

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
