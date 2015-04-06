"""Common utilities for letsencrypt.client.nginx."""
import os
import pkg_resources
import shutil
import tempfile
import unittest

import mock

from letsencrypt.client import constants
from letsencrypt.client.plugins.nginx import configurator
from letsencrypt.client.plugins.nginx import obj


class NginxTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def setUp(self):
        super(NginxTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = dir_setup(
            "debian_nginx_2_4/two_vhost_80")

        self.ssl_options = setup_nginx_ssl_options(self.config_dir)

        self.config_path = os.path.join(
            self.temp_dir, "debian_nginx_2_4/two_vhost_80/nginx2")

        self.rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.client.tests", "testdata/rsa256_key.pem")
        self.rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.client.tests", "testdata/rsa256_key.pem")


def get_data_filename(filename):
    return pkg_resources.resource_filename(
        "letsencrypt.client.plugins.nginx.tests", "testdata/%s" % filename)


def dir_setup(test_dir="debian_nginx_2_4/two_vhost_80"):
    """Setup the directories necessary for the configurator."""
    temp_dir = tempfile.mkdtemp("temp")
    config_dir = tempfile.mkdtemp("config")
    work_dir = tempfile.mkdtemp("work")

    test_configs = pkg_resources.resource_filename(
        "letsencrypt.client.plugins.nginx.tests", "testdata/%s" % test_dir)

    shutil.copytree(
        test_configs, os.path.join(temp_dir, test_dir), symlinks=True)

    return temp_dir, config_dir, work_dir


def setup_nginx_ssl_options(config_dir):
    """Move the ssl_options into position and return the path."""
    option_path = os.path.join(config_dir, "options-ssl.conf")
    shutil.copyfile(constants.APACHE_MOD_SSL_CONF, option_path)
    return option_path


def get_nginx_configurator(
        config_path, config_dir, work_dir, ssl_options, version=(2, 4, 7)):
    """Create an Nginx Configurator with the specified options."""

    backups = os.path.join(work_dir, "backups")

    with mock.patch("letsencrypt.client.plugins.nginx.configurator."
                    "subprocess.Popen") as mock_popen:
        # This just states that the ssl module is already loaded
        mock_popen().communicate.return_value = ("ssl_module", "")
        config = configurator.NginxConfigurator(
            mock.MagicMock(
                nginx_server_root=config_path,
                nginx_mod_ssl_conf=ssl_options,
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
    if config_name == "debian_nginx_2_4/two_vhost_80":
        prefix = os.path.join(
            temp_dir, config_name, "nginx2/sites-available")
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
