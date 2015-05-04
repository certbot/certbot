"""Common utilities for letsencrypt.client.plugins.apache."""
import os
import pkg_resources
import shutil
import tempfile
import unittest

import mock

from letsencrypt.client import constants
from letsencrypt.client.plugins.apache import configurator
from letsencrypt.client.plugins.apache import obj


class ApacheTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def setUp(self):
        super(ApacheTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = dir_setup(
            "debian_apache_2_4/two_vhost_80")

        self.ssl_options = setup_apache_ssl_options(self.config_dir)

        self.config_path = os.path.join(
            self.temp_dir, "debian_apache_2_4/two_vhost_80/apache2")

        self.rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")
        self.rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")


def dir_setup(test_dir="debian_apache_2_4/two_vhost_80"):
    """Setup the directories necessary for the configurator."""
    temp_dir = tempfile.mkdtemp("temp")
    config_dir = tempfile.mkdtemp("config")
    work_dir = tempfile.mkdtemp("work")

    os.chmod(temp_dir, constants.CONFIG_DIRS_MODE)
    os.chmod(config_dir, constants.CONFIG_DIRS_MODE)
    os.chmod(work_dir, constants.CONFIG_DIRS_MODE)

    test_configs = pkg_resources.resource_filename(
        "letsencrypt.client.plugins.apache.tests", "testdata/%s" % test_dir)

    shutil.copytree(
        test_configs, os.path.join(temp_dir, test_dir), symlinks=True)

    return temp_dir, config_dir, work_dir


def setup_apache_ssl_options(config_dir):
    """Move the ssl_options into position and return the path."""
    option_path = os.path.join(config_dir, "options-ssl.conf")
    shutil.copyfile(constants.APACHE_MOD_SSL_CONF, option_path)
    return option_path


def get_apache_configurator(
        config_path, config_dir, work_dir, ssl_options, version=(2, 4, 7)):
    """Create an Apache Configurator with the specified options."""

    backups = os.path.join(work_dir, "backups")

    with mock.patch("letsencrypt.client.plugins.apache.configurator."
                    "subprocess.Popen") as mock_popen:
        # This just states that the ssl module is already loaded
        mock_popen().communicate.return_value = ("ssl_module", "")
        config = configurator.ApacheConfigurator(
            mock.MagicMock(
                apache_server_root=config_path,
                apache_mod_ssl_conf=ssl_options,
                le_vhost_ext="-le-ssl.conf",
                backup_dir=backups,
                config_dir=config_dir,
                temp_checkpoint_dir=os.path.join(work_dir, "temp_checkpoints"),
                in_progress_dir=os.path.join(backups, "IN_PROGRESS"),
                work_dir=work_dir),
            version)

    config.prepare()

    return config


def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    if config_name == "debian_apache_2_4/two_vhost_80":
        prefix = os.path.join(
            temp_dir, config_name, "apache2/sites-available")
        aug_pre = "/files" + prefix
        vh_truth = [
            obj.VirtualHost(
                os.path.join(prefix, "encryption-example.conf"),
                os.path.join(aug_pre, "encryption-example.conf/VirtualHost"),
                set([obj.Addr.fromstring("*:80")]),
                False, True, set(["encryption-example.demo"])),
            obj.VirtualHost(
                os.path.join(prefix, "default-ssl.conf"),
                os.path.join(aug_pre, "default-ssl.conf/IfModule/VirtualHost"),
                set([obj.Addr.fromstring("_default_:443")]), True, False),
            obj.VirtualHost(
                os.path.join(prefix, "000-default.conf"),
                os.path.join(aug_pre, "000-default.conf/VirtualHost"),
                set([obj.Addr.fromstring("*:80")]), False, True,
                set(["ip-172-30-0-17"])),
            obj.VirtualHost(
                os.path.join(prefix, "letsencrypt.conf"),
                os.path.join(aug_pre, "letsencrypt.conf/VirtualHost"),
                set([obj.Addr.fromstring("*:80")]), False, True,
                set(["letsencrypt.demo"])),
        ]
        return vh_truth

    return None
