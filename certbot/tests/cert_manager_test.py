"""Tests for certbot.cert_manager."""
# pylint disable=protected-access
import datetime
import os
import shutil
import tempfile
import unittest

import configobj
import mock
import pytz
import six

import certbot
from certbot import cli
from certbot import configuration
from certbot import errors
from certbot import storage
from certbot.storage import ALL_FOUR

from certbot.tests import test_util


CERT = test_util.load_cert('cert.pem')


def unlink_all(rc_object):
    """Unlink all four items associated with this RenewableCert."""
    for kind in ALL_FOUR:
        os.unlink(getattr(rc_object, kind))


def fill_with_sample_data(rc_object):
    """Put dummy data into all four files of this RenewableCert."""
    for kind in ALL_FOUR:
        with open(getattr(rc_object, kind), "w") as f:
            f.write(kind)


class CertManagerTest(unittest.TestCase):
    """Tests for certbot.cert_manager
    """
    def setUp(self):
        from certbot import cert_manager
        self.tempdir = tempfile.mkdtemp()

        self.cli_config = configuration.RenewerConfiguration(
            namespace=mock.MagicMock(
                config_dir=self.tempdir,
                work_dir=self.tempdir,
                logs_dir=self.tempdir,
            )
        )

        os.makedirs(os.path.join(self.tempdir, "renewal"))
        self.domains = {
            "example.org": None,
            "other.com": os.path.join(self.tempdir, "specialarchive")
        }
        self.configs = {
            domain: self._set_up_config(domain, self.domains[domain])
            for domain in self.domains
        }

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
            live_dir_path = os.path.join(self.tempdir, "live", domain)
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

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
