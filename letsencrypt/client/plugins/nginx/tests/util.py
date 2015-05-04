"""Common utilities for letsencrypt.client.nginx."""
import os
import pkg_resources
import shutil
import tempfile
import unittest

import mock

from letsencrypt.client import constants
from letsencrypt.client.plugins.nginx import configurator


class NginxTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def setUp(self):
        super(NginxTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = dir_setup(
            "testdata")

        self.ssl_options = setup_nginx_ssl_options(self.config_dir)

        self.config_path = os.path.join(
            self.temp_dir, "testdata")

        self.rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")
        self.rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")


def get_data_filename(filename):
    """Gets the filename of a test data file."""
    return pkg_resources.resource_filename(
        "letsencrypt.client.plugins.nginx.tests", "testdata/%s" % filename)


def dir_setup(test_dir="debian_nginx/two_vhost_80"):
    """Setup the directories necessary for the configurator."""
    temp_dir = tempfile.mkdtemp("temp")
    config_dir = tempfile.mkdtemp("config")
    work_dir = tempfile.mkdtemp("work")

    os.chmod(temp_dir, constants.CONFIG_DIRS_MODE)
    os.chmod(config_dir, constants.CONFIG_DIRS_MODE)
    os.chmod(work_dir, constants.CONFIG_DIRS_MODE)

    test_configs = pkg_resources.resource_filename(
        "letsencrypt.client.plugins.nginx.tests", test_dir)

    shutil.copytree(
        test_configs, os.path.join(temp_dir, test_dir), symlinks=True)

    return temp_dir, config_dir, work_dir


def setup_nginx_ssl_options(config_dir):
    """Move the ssl_options into position and return the path."""
    option_path = os.path.join(config_dir, "options-ssl.conf")
    shutil.copyfile(constants.NGINX_MOD_SSL_CONF, option_path)
    return option_path


def get_nginx_configurator(
        config_path, config_dir, work_dir, ssl_options, version=(1, 6, 2)):
    """Create an Nginx Configurator with the specified options."""

    backups = os.path.join(work_dir, "backups")

    config = configurator.NginxConfigurator(
        mock.MagicMock(
            nginx_server_root=config_path, nginx_mod_ssl_conf=ssl_options,
            le_vhost_ext="-le-ssl.conf", backup_dir=backups,
            config_dir=config_dir, work_dir=work_dir,
            temp_checkpoint_dir=os.path.join(work_dir, "temp_checkpoints"),
            in_progress_dir=os.path.join(backups, "IN_PROGRESS")),
        version)
    config.prepare()
    return config
