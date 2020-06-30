"""Common utilities for certbot_apache."""
import shutil
import sys
import unittest

import augeas
import josepy as jose
try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore
import zope.component

from certbot.compat import os
from certbot.display import util as display_util
from certbot.plugins import common
from certbot.tests import util as test_util
from certbot_apache._internal import configurator
from certbot_apache._internal import entrypoint
from certbot_apache._internal import obj


class ApacheTest(unittest.TestCase):

    def setUp(self, test_dir="debian_apache_2_4/multiple_vhosts",
              config_root="debian_apache_2_4/multiple_vhosts/apache2",
              vhost_root="debian_apache_2_4/multiple_vhosts/apache2/sites-available"):
        # pylint: disable=arguments-differ
        super(ApacheTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = common.dir_setup(
            test_dir=test_dir,
            pkg=__name__)

        self.config_path = os.path.join(self.temp_dir, config_root)
        self.vhost_path = os.path.join(self.temp_dir, vhost_root)

        self.rsa512jwk = jose.JWKRSA.load(test_util.load_vector(
            "rsa512_key.pem"))

        self.config = get_apache_configurator(self.config_path, vhost_root,
                                              self.config_dir, self.work_dir)

        # Make sure all vhosts in sites-enabled are symlinks (Python packaging
        # does not preserve symlinks)
        sites_enabled = os.path.join(self.config_path, "sites-enabled")
        if not os.path.exists(sites_enabled):
            return

        for vhost_basename in os.listdir(sites_enabled):
            # Keep the one non-symlink test vhost in place
            if vhost_basename == "non-symlink.conf":
                continue
            vhost = os.path.join(sites_enabled, vhost_basename)
            if not os.path.islink(vhost):  # pragma: no cover
                os.remove(vhost)
                target = os.path.join(
                    os.path.pardir, "sites-available", vhost_basename)
                os.symlink(target, vhost)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)


class ParserTest(ApacheTest):

    def setUp(self, test_dir="debian_apache_2_4/multiple_vhosts",
              config_root="debian_apache_2_4/multiple_vhosts/apache2",
              vhost_root="debian_apache_2_4/multiple_vhosts/apache2/sites-available"):
        super(ParserTest, self).setUp(test_dir, config_root, vhost_root)

        zope.component.provideUtility(display_util.FileDisplay(sys.stdout,
                                                               False))

        from certbot_apache._internal.parser import ApacheParser
        self.aug = augeas.Augeas(
            flags=augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD)
        with mock.patch("certbot_apache._internal.parser.ApacheParser."
                        "update_runtime_variables"):
            self.parser = ApacheParser(
                self.config_path, self.vhost_path, configurator=self.config)


def get_apache_configurator(
        config_path, vhost_path,
        config_dir, work_dir, version=(2, 4, 7),
        os_info="generic",
        conf_vhost_path=None,
        use_parsernode=False,
        openssl_version="1.1.1a"):
    """Create an Apache Configurator with the specified options.

    :param conf: Function that returns binary paths. self.conf in Configurator

    """
    backups = os.path.join(work_dir, "backups")
    mock_le_config = mock.MagicMock(
        apache_server_root=config_path,
        apache_vhost_root=None,
        apache_le_vhost_ext="-le-ssl.conf",
        apache_challenge_location=config_path,
        apache_enmod=None,
        backup_dir=backups,
        config_dir=config_dir,
        http01_port=80,
        temp_checkpoint_dir=os.path.join(work_dir, "temp_checkpoints"),
        in_progress_dir=os.path.join(backups, "IN_PROGRESS"),
        work_dir=work_dir)

    with mock.patch("certbot_apache._internal.configurator.util.run_script"):
        with mock.patch("certbot_apache._internal.configurator.util."
                        "exe_exists") as mock_exe_exists:
            mock_exe_exists.return_value = True
            with mock.patch("certbot_apache._internal.parser.ApacheParser."
                            "update_runtime_variables"):
                with mock.patch("certbot_apache._internal.apache_util.parse_from_subprocess") as mock_sp:
                    mock_sp.return_value = []
                    try:
                        config_class = entrypoint.OVERRIDE_CLASSES[os_info]
                    except KeyError:
                        config_class = configurator.ApacheConfigurator
                    config = config_class(config=mock_le_config, name="apache",
                                          version=version, use_parsernode=use_parsernode,
                                          openssl_version=openssl_version)
                    if not conf_vhost_path:
                        config_class.OS_DEFAULTS["vhost_root"] = vhost_path
                    else:
                        # Custom virtualhost path was requested
                        config.config.apache_vhost_root = conf_vhost_path
                    config.config.apache_ctl = config_class.OS_DEFAULTS["ctl"]
                    config.prepare()
    return config


def get_vh_truth(temp_dir, config_name):
    """Return the ground truth for the specified directory."""
    if config_name == "debian_apache_2_4/multiple_vhosts":
        prefix = os.path.join(
            temp_dir, config_name, "apache2/sites-enabled")

        aug_pre = "/files" + prefix
        vh_truth = [
            obj.VirtualHost(
                os.path.join(prefix, "encryption-example.conf"),
                os.path.join(aug_pre, "encryption-example.conf/Virtualhost"),
                {obj.Addr.fromstring("*:80")},
                False, True, "encryption-example.demo"),
            obj.VirtualHost(
                os.path.join(prefix, "default-ssl.conf"),
                os.path.join(aug_pre,
                             "default-ssl.conf/IfModule/VirtualHost"),
                {obj.Addr.fromstring("_default_:443")}, True, True),
            obj.VirtualHost(
                os.path.join(prefix, "000-default.conf"),
                os.path.join(aug_pre, "000-default.conf/VirtualHost"),
                {obj.Addr.fromstring("*:80"),
                     obj.Addr.fromstring("[::]:80")},
                False, True, "ip-172-30-0-17"),
            obj.VirtualHost(
                os.path.join(prefix, "certbot.conf"),
                os.path.join(aug_pre, "certbot.conf/VirtualHost"),
                {obj.Addr.fromstring("*:80")}, False, True,
                "certbot.demo", aliases=["www.certbot.demo"]),
            obj.VirtualHost(
                os.path.join(prefix, "mod_macro-example.conf"),
                os.path.join(aug_pre,
                             "mod_macro-example.conf/Macro/VirtualHost"),
                {obj.Addr.fromstring("*:80")}, False, True,
                modmacro=True),
            obj.VirtualHost(
                os.path.join(prefix, "default-ssl-port-only.conf"),
                os.path.join(aug_pre, ("default-ssl-port-only.conf/"
                                       "IfModule/VirtualHost")),
                {obj.Addr.fromstring("_default_:443")}, True, True),
            obj.VirtualHost(
                os.path.join(prefix, "wildcard.conf"),
                os.path.join(aug_pre, "wildcard.conf/VirtualHost"),
                {obj.Addr.fromstring("*:80")}, False, True,
                "ip-172-30-0-17", aliases=["*.blue.purple.com"]),
            obj.VirtualHost(
                os.path.join(prefix, "ocsp-ssl.conf"),
                os.path.join(aug_pre, "ocsp-ssl.conf/IfModule/VirtualHost"),
                {obj.Addr.fromstring("10.2.3.4:443")}, True, True,
                "ocspvhost.com"),
            obj.VirtualHost(
                os.path.join(prefix, "non-symlink.conf"),
                os.path.join(aug_pre, "non-symlink.conf/VirtualHost"),
                {obj.Addr.fromstring("*:80")}, False, True,
                "nonsym.link"),
            obj.VirtualHost(
                os.path.join(prefix, "default-ssl-port-only.conf"),
                os.path.join(aug_pre,
                             "default-ssl-port-only.conf/VirtualHost"),
                {obj.Addr.fromstring("*:80")}, True, True, ""),
            obj.VirtualHost(
                os.path.join(temp_dir, config_name,
                             "apache2/apache2.conf"),
                "/files" + os.path.join(temp_dir, config_name,
                                        "apache2/apache2.conf/VirtualHost"),
                {obj.Addr.fromstring("*:80")}, False, True,
                "vhost.in.rootconf"),
            obj.VirtualHost(
                os.path.join(prefix, "duplicatehttp.conf"),
                os.path.join(aug_pre, "duplicatehttp.conf/VirtualHost"),
                {obj.Addr.fromstring("10.2.3.4:80")}, False, True,
                "duplicate.example.com"),
            obj.VirtualHost(
                os.path.join(prefix, "duplicatehttps.conf"),
                os.path.join(aug_pre, "duplicatehttps.conf/IfModule/VirtualHost"),
                {obj.Addr.fromstring("10.2.3.4:443")}, True, True,
                "duplicate.example.com")]
        return vh_truth
    if config_name == "debian_apache_2_4/multi_vhosts":
        prefix = os.path.join(
            temp_dir, config_name, "apache2/sites-available")
        aug_pre = "/files" + prefix
        vh_truth = [
            obj.VirtualHost(
                os.path.join(prefix, "default.conf"),
                os.path.join(aug_pre, "default.conf/VirtualHost[1]"),
                {obj.Addr.fromstring("*:80")},
                False, True, "ip-172-30-0-17"),
            obj.VirtualHost(
                os.path.join(prefix, "default.conf"),
                os.path.join(aug_pre, "default.conf/VirtualHost[2]"),
                {obj.Addr.fromstring("*:80")},
                False, True, "banana.vomit.com"),
            obj.VirtualHost(
                os.path.join(prefix, "multi-vhost.conf"),
                os.path.join(aug_pre, "multi-vhost.conf/VirtualHost[1]"),
                {obj.Addr.fromstring("*:80")},
                False, True, "1.multi.vhost.tld"),
            obj.VirtualHost(
                os.path.join(prefix, "multi-vhost.conf"),
                os.path.join(aug_pre, "multi-vhost.conf/IfModule/VirtualHost"),
                {obj.Addr.fromstring("*:80")},
                False, True, "2.multi.vhost.tld"),
            obj.VirtualHost(
                os.path.join(prefix, "multi-vhost.conf"),
                os.path.join(aug_pre, "multi-vhost.conf/VirtualHost[2]"),
                {obj.Addr.fromstring("*:80")},
                False, True, "3.multi.vhost.tld")]
        return vh_truth
    return None  # pragma: no cover
