"""Common utilities for letsencrypt_apache."""
import os
import pkg_resources
import unittest

import mock

from letsencrypt.plugins import common

from letsencrypt_apache import configurator
from letsencrypt_apache import constants
from letsencrypt_apache import obj


class ApacheTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def setUp(self):
        super(ApacheTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = common.dir_setup(
            test_dir="debian_apache_2_4/two_vhost_80",
            pkg="letsencrypt_apache.tests")

        self.ssl_options = common.setup_ssl_options(
            self.config_dir, constants.MOD_SSL_CONF_SRC,
            constants.MOD_SSL_CONF_DEST)

        self.config_path = os.path.join(
            self.temp_dir, "debian_apache_2_4/two_vhost_80/apache2")

        self.rsa256_file = pkg_resources.resource_filename(
            "letsencrypt.tests", os.path.join("testdata", "rsa256_key.pem"))
        self.rsa256_pem = pkg_resources.resource_string(
            "letsencrypt.tests", os.path.join("testdata", "rsa256_key.pem"))


def get_apache_configurator(
        config_path, config_dir, work_dir, version=(2, 4, 7), conf=None):
    """Create an Apache Configurator with the specified options.

    :param conf: Function that returns binary paths. self.conf in Configurator

    """
    backups = os.path.join(work_dir, "backups")

    with mock.patch("letsencrypt_apache.configurator."
                    "subprocess.Popen") as mock_popen:
        with mock.patch("letsencrypt_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            # This indicates config_test passes
            mock_popen().communicate.return_value = ("Fine output", "No problems")
            mock_popen().returncode = 0

            config = configurator.ApacheConfigurator(
                config=mock.MagicMock(
                    apache_server_root=config_path,
                    apache_le_vhost_ext=constants.CLI_DEFAULTS["le_vhost_ext"],
                    backup_dir=backups,
                    config_dir=config_dir,
                    temp_checkpoint_dir=os.path.join(work_dir, "temp_checkpoints"),
                    in_progress_dir=os.path.join(backups, "IN_PROGRESS"),
                    work_dir=work_dir),
                name="apache",
                version=version)
            # This allows testing scripts to set it a bit more quickly
            if conf is not None:
                config.conf = conf

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
