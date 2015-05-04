"""Common utilities for letsencrypt.client.nginx."""
import os
import pkg_resources
import unittest

import mock

from letsencrypt.client import constants

from letsencrypt.client.plugins.apache.tests import util as apache_util
from letsencrypt.client.plugins.nginx import configurator


class NginxTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def setUp(self):
        super(NginxTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = apache_util.dir_setup(
            "etc_nginx", "letsencrypt.client.plugins.nginx.tests")

        self.ssl_options = apache_util.setup_ssl_options(
            self.config_dir, constants.NGINX_MOD_SSL_CONF)

        self.config_path = os.path.join(self.temp_dir, "etc_nginx")

        self.rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")
        self.rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.acme.jose", "testdata/rsa256_key.pem")


def get_data_filename(filename):
    """Gets the filename of a test data file."""
    return pkg_resources.resource_filename(
        "letsencrypt.client.plugins.nginx.tests", os.path.join(
            "testdata", "etc_nginx", filename))


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
