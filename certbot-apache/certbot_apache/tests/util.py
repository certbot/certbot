"""Common utilities for certbot_apache."""
import os
import sys
import unittest

import augeas
import mock
import zope.component

from acme import jose

from certbot.display import util as display_util

from certbot.plugins import common

from certbot.tests import test_util

from certbot_apache import configurator
from certbot_apache import constants
from certbot_apache import obj


class ApacheTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def setUp(self, test_dir="debian_apache_2_4/multiple_vhosts",
              config_root="debian_apache_2_4/multiple_vhosts/apache2",
              vhost_root="debian_apache_2_4/multiple_vhosts/apache2/sites-available"):
        # pylint: disable=arguments-differ
        super(ApacheTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = common.dir_setup(
            test_dir=test_dir,
            pkg="certbot_apache.tests")

        self.ssl_options = common.setup_ssl_options(
            self.config_dir, constants.os_constant("MOD_SSL_CONF_SRC"),
            constants.MOD_SSL_CONF_DEST)

        self.config_path = os.path.join(self.temp_dir, config_root)
        self.vhost_path = os.path.join(self.temp_dir, vhost_root)

        self.rsa512jwk = jose.JWKRSA.load(test_util.load_vector(
            "rsa512_key.pem"))

        # Make sure all vhosts in sites-enabled are symlinks (Python packaging
        # does not preserve symlinks)
        sites_enabled = os.path.join(self.config_path, "sites-enabled")
        if not os.path.exists(sites_enabled):
            return

        for vhost_basename in os.listdir(sites_enabled):
            vhost = os.path.join(sites_enabled, vhost_basename)
            if not os.path.islink(vhost):  # pragma: no cover
                os.remove(vhost)
                target = os.path.join(
                    os.path.pardir, "sites-available", vhost_basename)
                os.symlink(target, vhost)


class ParserTest(ApacheTest):  # pytlint: disable=too-few-public-methods

    def setUp(self, test_dir="debian_apache_2_4/multiple_vhosts",
              config_root="debian_apache_2_4/multiple_vhosts/apache2",
              vhost_root="debian_apache_2_4/multiple_vhosts/apache2/sites-available"):
        super(ParserTest, self).setUp(test_dir, config_root, vhost_root)

        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

        from certbot_apache.parser import ApacheParser
        self.aug = augeas.Augeas(
            flags=augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD)
        with mock.patch("certbot_apache.parser.ApacheParser."
                        "update_runtime_variables"):
            self.parser = ApacheParser(
                self.aug, self.config_path, self.vhost_path)


def get_apache_configurator(
        config_path, vhost_path,
        config_dir, work_dir, version=(2, 4, 7), conf=None):
    """Create an Apache Configurator with the specified options.

    :param conf: Function that returns binary paths. self.conf in Configurator

    """
    backups = os.path.join(work_dir, "backups")
    mock_le_config = mock.MagicMock(
        apache_server_root=config_path,
        apache_vhost_root=vhost_path,
        apache_le_vhost_ext=constants.os_constant("le_vhost_ext"),
        apache_challenge_location=config_path,
        backup_dir=backups,
        config_dir=config_dir,
        temp_checkpoint_dir=os.path.join(work_dir, "temp_checkpoints"),
        in_progress_dir=os.path.join(backups, "IN_PROGRESS"),
        work_dir=work_dir)

    with mock.patch("certbot_apache.configurator.util.run_script"):
        with mock.patch("certbot_apache.configurator.util."
                        "exe_exists") as mock_exe_exists:
            mock_exe_exists.return_value = True
            with mock.patch("certbot_apache.parser.ApacheParser."
                            "update_runtime_variables"):
                config = configurator.ApacheConfigurator(
                    config=mock_le_config,
                    name="apache",
                    version=version)
                # This allows testing scripts to set it a bit more quickly
                if conf is not None:
                    config.conf = conf  # pragma: no cover

                config.prepare()

    return config


def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    if config_name == "debian_apache_2_4/multiple_vhosts":
        prefix = os.path.join(
            temp_dir, config_name, "apache2/sites-available")
        aug_pre = "/files" + prefix
        vh_truth = [
            obj.VirtualHost(
                os.path.join(prefix, "encryption-example.conf"),
                os.path.join(aug_pre, "encryption-example.conf/VirtualHost"),
                set([obj.Addr.fromstring("*:80")]),
                False, True, "encryption-example.demo"),
            obj.VirtualHost(
                os.path.join(prefix, "default-ssl.conf"),
                os.path.join(aug_pre, "default-ssl.conf/IfModule/VirtualHost"),
                set([obj.Addr.fromstring("_default_:443")]), True, False),
            obj.VirtualHost(
                os.path.join(prefix, "000-default.conf"),
                os.path.join(aug_pre, "000-default.conf/VirtualHost"),
                set([obj.Addr.fromstring("*:80"),
                     obj.Addr.fromstring("[::]:80")]),
                False, True, "ip-172-30-0-17"),
            obj.VirtualHost(
                os.path.join(prefix, "certbot.conf"),
                os.path.join(aug_pre, "certbot.conf/VirtualHost"),
                set([obj.Addr.fromstring("*:80")]), False, True,
                "certbot.demo"),
            obj.VirtualHost(
                os.path.join(prefix, "mod_macro-example.conf"),
                os.path.join(aug_pre,
                             "mod_macro-example.conf/Macro/VirtualHost"),
                set([obj.Addr.fromstring("*:80")]), False, True,
                modmacro=True),
            obj.VirtualHost(
                os.path.join(prefix, "default-ssl-port-only.conf"),
                os.path.join(aug_pre, ("default-ssl-port-only.conf/"
                                       "IfModule/VirtualHost")),
                set([obj.Addr.fromstring("_default_:443")]), True, False),
            obj.VirtualHost(
                os.path.join(prefix, "wildcard.conf"),
                os.path.join(aug_pre, "wildcard.conf/VirtualHost"),
                set([obj.Addr.fromstring("*:80")]), False, False,
                "ip-172-30-0-17", aliases=["*.blue.purple.com"]),
            obj.VirtualHost(
                os.path.join(prefix, "ocsp-ssl.conf"),
                os.path.join(aug_pre, "ocsp-ssl.conf/IfModule/VirtualHost"),
                set([obj.Addr.fromstring("10.2.3.4:443")]), True, True,
                "ocspvhost.com")]
        return vh_truth

    return None  # pragma: no cover
