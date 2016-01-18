"""Common utilities for letsencrypt_nginx."""
import os
import pkg_resources
import unittest

import mock
import zope.component

from acme import jose

from letsencrypt import configuration

from letsencrypt.tests import test_util

from letsencrypt.plugins import common

from letsencrypt_nginx import constants
from letsencrypt_nginx import configurator


class NginxTest(unittest.TestCase):  # pylint: disable=too-few-public-methods

    def setUp(self):
        super(NginxTest, self).setUp()

        self.temp_dir, self.config_dir, self.work_dir = common.dir_setup(
            "etc_nginx", "letsencrypt_nginx.tests")

        self.ssl_options = common.setup_ssl_options(
            self.config_dir, constants.MOD_SSL_CONF_SRC,
            constants.MOD_SSL_CONF_DEST)

        self.config_path = os.path.join(self.temp_dir, "etc_nginx")

        self.rsa512jwk = jose.JWKRSA.load(test_util.load_vector(
            "rsa512_key.pem"))


def get_data_filename(filename):
    """Gets the filename of a test data file."""
    return pkg_resources.resource_filename(
        "letsencrypt_nginx.tests", os.path.join(
            "testdata", "etc_nginx", filename))


def get_nginx_configurator(
        config_path, config_dir, work_dir, version=(1, 6, 2)):
    """Create an Nginx Configurator with the specified options."""

    backups = os.path.join(work_dir, "backups")

    with mock.patch("letsencrypt_nginx.configurator.le_util."
                    "exe_exists") as mock_exe_exists:
        mock_exe_exists.return_value = True

        config = configurator.NginxConfigurator(
            config=mock.MagicMock(
                nginx_server_root=config_path,
                le_vhost_ext="-le-ssl.conf",
                config_dir=config_dir,
                work_dir=work_dir,
                backup_dir=backups,
                temp_checkpoint_dir=os.path.join(work_dir, "temp_checkpoints"),
                in_progress_dir=os.path.join(backups, "IN_PROGRESS"),
                server="https://acme-server.org:443/new",
                tls_sni_01_port=5001,
            ),
            name="nginx",
            version=version)
        config.prepare()

    # Provide general config utility.
    nsconfig = configuration.NamespaceConfig(config.config)
    zope.component.provideUtility(nsconfig)

    return config


def filter_comments(tree):
    """Filter comment nodes from parsed configurations."""

    def traverse(tree):
        """Generator dropping comment nodes"""
        for key, values in tree:
            if isinstance(key, list):
                yield [key, filter_comments(values)]
            else:
                if key != '#':
                    yield [key, values]

    return list(traverse(tree))


def contains_at_depth(haystack, needle, n):
    """Is the needle in haystack at depth n?

    Return true if the needle is present in one of the sub-iterables in haystack
    at depth n. Haystack must be an iterable.
    """
    # Specifically use hasattr rather than isinstance(..., collections.Iterable)
    # because we want to include lists but reject strings.
    if not hasattr(haystack, '__iter__'):
        return False
    if n == 0:
        return needle in haystack
    else:
        for item in haystack:
            if contains_at_depth(item, needle, n - 1):
                return True
        return False
