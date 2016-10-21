"""Tests for certbot.cert_manager."""
# pylint disable=protected-access
import os
import shutil
import tempfile
import unittest

import configobj
import mock

from certbot import configuration
from certbot.storage import ALL_FOUR

class CertManagerTest(unittest.TestCase):
    """Tests for certbot.cert_manager
    """
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

        os.makedirs(os.path.join(self.tempdir, "renewal"))

        mock_namespace = mock.MagicMock(
            config_dir=self.tempdir,
            work_dir=self.tempdir,
            logs_dir=self.tempdir,
            quiet=False,
        )

        self.cli_config = configuration.RenewerConfiguration(
            namespace=mock_namespace
        )

        self.domains = {
            "example.org": None,
            "other.com": os.path.join(self.tempdir, "specialarchive")
        }
        self.configs = dict((domain, self._set_up_config(domain, self.domains[domain]))
            for domain in self.domains)

        # We also create a file that isn't a renewal config in the same
        # location to test that logic that reads in all-and-only renewal
        # configs will ignore it and NOT attempt to parse it.
        junk = open(os.path.join(self.tempdir, "renewal", "IGNORE.THIS"), "w")
        junk.write("This file should be ignored!")
        junk.close()

    def _set_up_config(self, domain, custom_archive):
        # TODO: maybe provide RenewerConfiguration.make_dirs?
        # TODO: main() should create those dirs, c.f. #902
        os.makedirs(os.path.join(self.tempdir, "live", domain))
        config = configobj.ConfigObj()

        if custom_archive is not None:
            os.makedirs(custom_archive)
            config["archive_dir"] = custom_archive
        else:
            os.makedirs(os.path.join(self.tempdir, "archive", domain))

        for kind in ALL_FOUR:
            config[kind] = os.path.join(self.tempdir, "live", domain,
                                        kind + ".pem")

        config.filename = os.path.join(self.tempdir, "renewal",
                                       domain + ".conf")
        config.write()
        return config

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_update_live_symlinks(self):
        """Test update_live_symlinks"""
        # pylint: disable=too-many-statements
        # create files with incorrect symlinks
        from certbot import cert_manager
        archive_paths = {}
        for domain in self.domains:
            custom_archive = self.domains[domain]
            if custom_archive is not None:
                archive_dir_path = custom_archive
            else:
                archive_dir_path = os.path.join(self.tempdir, "archive", domain)
            archive_paths[domain] = {kind: os.path.join(archive_dir_path, kind + "1.pem")
                for kind in ALL_FOUR}
            for kind in ALL_FOUR:
                live_path = self.configs[domain][kind]
                archive_path = archive_paths[domain][kind]
                open(archive_path, 'a').close()
                # path is incorrect but base must be correct
                os.symlink(os.path.join(self.tempdir, kind + "1.pem"), live_path)

        # run update symlinks
        cert_manager.update_live_symlinks(self.cli_config)

        # check that symlinks go where they should
        for domain in self.domains:
            for kind in ALL_FOUR:
                self.assertEqual(os.readlink(self.configs[domain][kind]),
                    archive_paths[domain][kind])

    @mock.patch('zope.component.getUtility')
    def test_list_certs_parse_fail(self, mock_utility):
        from certbot import cert_manager

        with mock.patch("certbot.cert_manager.logger") as mock_logger:
            cert_manager.list_certs(self.cli_config)
            self.assertTrue(mock_logger.warning.called)
        self.assertTrue(mock_utility.called)

    @mock.patch('zope.component.getUtility')
    @mock.patch("certbot.storage.RenewableCert")
    def test_list_certs_parse_success(self, mock_utility, mock_renewable_cert):
        from certbot import cert_manager
        with mock.patch("certbot.cert_manager.logger") as mock_logger:
            cert_manager.list_certs(self.cli_config)
            self.assertFalse(mock_logger.warning.called)
        self.assertTrue(mock_utility.called)

    @mock.patch('zope.component.getUtility')
    def test_list_certs_no_files(self, mock_utility):
        from certbot import cert_manager

        tempdir = tempfile.mkdtemp()

        cli_config = configuration.RenewerConfiguration(
            namespace=mock.MagicMock(
                config_dir=tempdir,
                work_dir=tempdir,
                logs_dir=tempdir,
                quiet=False,
            )
        )
        os.makedirs(os.path.join(tempdir, "renewal"))
        with mock.patch("certbot.cert_manager.logger") as mock_logger:
            cert_manager.list_certs(cli_config)
            self.assertFalse(mock_logger.warning.called)
        self.assertTrue(mock_utility.called)
        shutil.rmtree(tempdir)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
