"""Test letsencrypt.revoker."""
import csv
import os
import pkg_resources
import shutil
import tempfile
import unittest

import mock
import OpenSSL

from letsencrypt import errors
from letsencrypt import le_util
from letsencrypt.display import util as display_util


KEY = OpenSSL.crypto.load_privatekey(
    OpenSSL.crypto.FILETYPE_PEM, pkg_resources.resource_string(
        __name__, os.path.join("testdata", "rsa512_key.pem")))


class RevokerBase(unittest.TestCase):  # pylint: disable=too-few-public-methods
    """Base Class for Revoker Tests."""
    def setUp(self):
        self.paths, self.certs, self.key_path = create_revoker_certs()

        self.backup_dir = tempfile.mkdtemp("cert_backup")
        self.mock_config = mock.MagicMock(cert_key_backup=self.backup_dir)

        self.list_path = os.path.join(self.backup_dir, "LIST")

    def _store_certs(self):
        # pylint: disable=protected-access
        from letsencrypt.revoker import Revoker
        Revoker.store_cert_key(self.paths[0], self.key_path, self.mock_config)
        Revoker.store_cert_key(self.paths[1], self.key_path, self.mock_config)

        # Set metadata
        for i in xrange(2):
            self.certs[i].add_meta(
                i, self.paths[i], self.key_path,
                Revoker._get_backup(self.backup_dir, i, self.paths[i]),
                Revoker._get_backup(self.backup_dir, i, self.key_path))

    def _get_rows(self):
        with open(self.list_path, "rb") as csvfile:
            return [row for row in csv.reader(csvfile)]

    def _write_rows(self, rows):
        with open(self.list_path, "wb") as csvfile:
            csvwriter = csv.writer(csvfile)
            for row in rows:
                csvwriter.writerow(row)


class RevokerTest(RevokerBase):
    def setUp(self):
        from letsencrypt.revoker import Revoker
        super(RevokerTest, self).setUp()

        with open(self.key_path) as key_file:
            self.key = le_util.Key(self.key_path, key_file.read())

        self._store_certs()

        self.revoker = Revoker(
            installer=mock.MagicMock(), config=self.mock_config)

    def tearDown(self):
        shutil.rmtree(self.backup_dir)

    @mock.patch("letsencrypt.network.Network.revoke")
    @mock.patch("letsencrypt.revoker.revocation")
    def test_revoke_by_key_all(self, mock_display, mock_net):
        mock_display().confirm_revocation.return_value = True

        self.revoker.revoke_from_key(self.key)
        self.assertEqual(self._get_rows(), [])

        # Check to make sure backups were eliminated
        for i in xrange(2):
            self.assertFalse(self._backups_exist(self.certs[i].get_row()))

        self.assertEqual(mock_net.call_count, 2)

    @mock.patch("letsencrypt.revoker.OpenSSL.crypto.load_privatekey")
    def test_revoke_by_invalid_keys(self, mock_load_privatekey):
        mock_load_privatekey.side_effect = OpenSSL.crypto.Error
        self.assertRaises(
            errors.RevokerError, self.revoker.revoke_from_key, self.key)

        mock_load_privatekey.side_effect = [KEY, OpenSSL.crypto.Error]
        self.assertRaises(
            errors.RevokerError, self.revoker.revoke_from_key, self.key)

    @mock.patch("letsencrypt.network.Network.revoke")
    @mock.patch("letsencrypt.revoker.revocation")
    def test_revoke_by_wrong_key(self, mock_display, mock_net):
        mock_display().confirm_revocation.return_value = True

        key_path = pkg_resources.resource_filename(
            "acme.jose", os.path.join("testdata", "rsa256_key.pem"))

        wrong_key = le_util.Key(key_path, open(key_path).read())
        self.revoker.revoke_from_key(wrong_key)

        # Nothing was removed
        self.assertEqual(len(self._get_rows()), 2)
        # No revocation went through
        self.assertEqual(mock_net.call_count, 0)

    @mock.patch("letsencrypt.network.Network.revoke")
    @mock.patch("letsencrypt.revoker.revocation")
    def test_revoke_by_cert(self, mock_display, mock_net):
        mock_display().confirm_revocation.return_value = True

        self.revoker.revoke_from_cert(self.paths[1])

        row0 = self.certs[0].get_row()
        row1 = self.certs[1].get_row()

        self.assertEqual(self._get_rows(), [row0])

        self.assertTrue(self._backups_exist(row0))
        self.assertFalse(self._backups_exist(row1))

        self.assertEqual(mock_net.call_count, 1)

    @mock.patch("letsencrypt.network.Network.revoke")
    @mock.patch("letsencrypt.revoker.revocation")
    def test_revoke_by_cert_not_found(self, mock_display, mock_net):
        mock_display().confirm_revocation.return_value = True

        self.revoker.revoke_from_cert(self.paths[0])
        self.revoker.revoke_from_cert(self.paths[0])

        row0 = self.certs[0].get_row()
        row1 = self.certs[1].get_row()

        # Same check as last time... just reversed.
        self.assertEqual(self._get_rows(), [row1])

        self.assertTrue(self._backups_exist(row1))
        self.assertFalse(self._backups_exist(row0))

        self.assertEqual(mock_net.call_count, 1)

    @mock.patch("letsencrypt.network.Network.revoke")
    @mock.patch("letsencrypt.revoker.revocation")
    def test_revoke_by_menu(self, mock_display, mock_net):
        mock_display().confirm_revocation.return_value = True
        mock_display.display_certs.side_effect = [
            (display_util.HELP, 0),
            (display_util.OK, 0),
            (display_util.CANCEL, -1),
        ]

        self.revoker.revoke_from_menu()

        row0 = self.certs[0].get_row()
        row1 = self.certs[1].get_row()

        self.assertEqual(self._get_rows(), [row1])

        self.assertFalse(self._backups_exist(row0))
        self.assertTrue(self._backups_exist(row1))

        self.assertEqual(mock_net.call_count, 1)
        self.assertEqual(mock_display.more_info_cert.call_count, 1)

    @mock.patch("letsencrypt.revoker.logger")
    @mock.patch("letsencrypt.network.Network.revoke")
    @mock.patch("letsencrypt.revoker.revocation")
    def test_revoke_by_menu_delete_all(self, mock_display, mock_net, mock_log):
        mock_display().confirm_revocation.return_value = True
        mock_display.display_certs.return_value = (display_util.OK, 0)

        self.revoker.revoke_from_menu()

        self.assertEqual(self._get_rows(), [])

        # Everything should be deleted...
        for i in xrange(2):
            self.assertFalse(self._backups_exist(self.certs[i].get_row()))

        self.assertEqual(mock_net.call_count, 2)
        # Info is called when there aren't any certs left...
        self.assertTrue(mock_log.info.called)

    @mock.patch("letsencrypt.revoker.revocation")
    @mock.patch("letsencrypt.revoker.Revoker._acme_revoke")
    @mock.patch("letsencrypt.revoker.logger")
    def test_safe_revoke_acme_fail(self, mock_log, mock_revoke, mock_display):
        # pylint: disable=protected-access
        mock_revoke.side_effect = errors.Error
        mock_display().confirm_revocation.return_value = True

        self.revoker._safe_revoke(self.certs)
        self.assertTrue(mock_log.error.called)

    @mock.patch("letsencrypt.revoker.OpenSSL.crypto.load_privatekey")
    def test_acme_revoke_failure(self, mock_load_privatekey):
        # pylint: disable=protected-access
        mock_load_privatekey.side_effect = OpenSSL.crypto.Error
        self.assertRaises(
            errors.Error, self.revoker._acme_revoke, self.certs[0])

    def test_remove_certs_from_list_bad_certs(self):
        # pylint: disable=protected-access
        from letsencrypt.revoker import Cert

        new_cert = Cert(self.paths[0])

        # This isn't stored in the db
        new_cert.idx = 10
        new_cert.backup_path = self.paths[0]
        new_cert.backup_key_path = self.key_path
        new_cert.orig = Cert.PathStatus("false path", "not here")
        new_cert.orig_key = Cert.PathStatus("false path", "not here")

        self.assertRaises(errors.RevokerError,
                          self.revoker._remove_certs_from_list, [new_cert])

    def _backups_exist(self, row):
        # pylint: disable=protected-access
        cert_path, key_path = self.revoker._row_to_backup(row)
        return os.path.isfile(cert_path) and os.path.isfile(key_path)


class RevokerInstallerTest(RevokerBase):
    def setUp(self):
        super(RevokerInstallerTest, self).setUp()

        self.installs = [
            ["installation/path0a", "installation/path0b"],
            ["installation/path1"],
        ]

        self.certs_keys = [
            (self.paths[0], self.key_path, self.installs[0][0]),
            (self.paths[0], self.key_path, self.installs[0][1]),
            (self.paths[1], self.key_path, self.installs[1][0]),
        ]

        self._store_certs()

    def _get_revoker(self, installer):
        from letsencrypt.revoker import Revoker
        return Revoker(installer, self.mock_config)

    def test_no_installer_get_installed_locations(self):
        # pylint: disable=protected-access
        revoker = self._get_revoker(None)
        self.assertEqual(revoker._get_installed_locations(), {})

    def test_get_installed_locations(self):
        # pylint: disable=protected-access
        mock_installer = mock.MagicMock()
        mock_installer.get_all_certs_keys.return_value = self.certs_keys

        revoker = self._get_revoker(mock_installer)
        sha_vh = revoker._get_installed_locations()

        self.assertEqual(len(sha_vh), 2)
        for i, cert in enumerate(self.certs):
            self.assertTrue(cert.get_fingerprint() in sha_vh)
            self.assertEqual(
                sha_vh[cert.get_fingerprint()], self.installs[i])

    @mock.patch("letsencrypt.revoker.M2Crypto.X509.load_cert")
    def test_get_installed_load_failure(self, mock_m2):
        mock_installer = mock.MagicMock()
        mock_installer.get_all_certs_keys.return_value = self.certs_keys

        mock_m2.side_effect = IOError

        revoker = self._get_revoker(mock_installer)

        # pylint: disable=protected-access
        self.assertEqual(revoker._get_installed_locations(), {})


class RevokerClassMethodsTest(RevokerBase):
    def setUp(self):
        super(RevokerClassMethodsTest, self).setUp()
        self.mock_config = mock.MagicMock(cert_key_backup=self.backup_dir)

    def tearDown(self):
        shutil.rmtree(self.backup_dir)

    def _call(self, cert_path, key_path):
        from letsencrypt.revoker import Revoker
        Revoker.store_cert_key(cert_path, key_path, self.mock_config)

    def test_store_two(self):
        from letsencrypt.revoker import Revoker
        self._call(self.paths[0], self.key_path)
        self._call(self.paths[1], self.key_path)

        self.assertTrue(os.path.isfile(self.list_path))
        rows = self._get_rows()

        for i, row in enumerate(rows):
            # pylint: disable=protected-access
            self.assertTrue(os.path.isfile(
                Revoker._get_backup(self.backup_dir, i, self.paths[i])))
            self.assertTrue(os.path.isfile(
                Revoker._get_backup(self.backup_dir, i, self.key_path)))
            self.assertEqual([str(i), self.paths[i], self.key_path], row)

        self.assertEqual(len(rows), 2)

    def test_store_one_mixed(self):
        from letsencrypt.revoker import Revoker
        self._write_rows(
            [["5", "blank", "blank"], ["18", "dc", "dc"], ["21", "b", "b"]])
        self._call(self.paths[0], self.key_path)

        self.assertEqual(
            self._get_rows()[3], ["22", self.paths[0], self.key_path])

        # pylint: disable=protected-access
        self.assertTrue(os.path.isfile(
            Revoker._get_backup(self.backup_dir, 22, self.paths[0])))
        self.assertTrue(os.path.isfile(
            Revoker._get_backup(self.backup_dir, 22, self.key_path)))


class CertTest(unittest.TestCase):
    def setUp(self):
        self.paths, self.certs, self.key_path = create_revoker_certs()

    def test_failed_load(self):
        from letsencrypt.revoker import Cert
        self.assertRaises(errors.RevokerError, Cert, self.key_path)

    def test_no_row(self):
        self.assertEqual(self.certs[0].get_row(), None)

    def test_meta_moved_files(self):
        from letsencrypt.revoker import Cert
        fake_path = "/not/a/real/path/r72d3t6"
        self.certs[0].add_meta(
            0, fake_path, fake_path, self.paths[0], self.key_path)

        self.assertEqual(self.certs[0].orig.status, Cert.DELETED_MSG)
        self.assertEqual(self.certs[0].orig_key.status, Cert.DELETED_MSG)

    def test_meta_changed_files(self):
        from letsencrypt.revoker import Cert
        self.certs[0].add_meta(
            0, self.paths[1], self.paths[1], self.paths[0], self.key_path)

        self.assertEqual(self.certs[0].orig.status, Cert.CHANGED_MSG)
        self.assertEqual(self.certs[0].orig_key.status, Cert.CHANGED_MSG)

    def test_meta_no_status(self):
        self.certs[0].add_meta(
            0, self.paths[0], self.key_path, self.paths[0], self.key_path)

        self.assertEqual(self.certs[0].orig.status, "")
        self.assertEqual(self.certs[0].orig_key.status, "")

    def test_print_meta(self):
        """Just make sure there aren't any major errors."""
        self.certs[0].add_meta(
            0, self.paths[0], self.key_path, self.paths[0], self.key_path)
        # Changed path and deleted file
        self.certs[1].add_meta(
            1, self.paths[0], "/not/a/path", self.paths[1], self.key_path)
        self.assertTrue(self.certs[0].pretty_print())
        self.assertTrue(self.certs[1].pretty_print())

    def test_print_no_meta(self):
        self.assertTrue(self.certs[0].pretty_print())
        self.assertTrue(self.certs[1].pretty_print())


def create_revoker_certs():
    """Create a few revoker.Cert objects."""
    from letsencrypt.revoker import Cert

    base_package = "letsencrypt.tests"

    cert0_path = pkg_resources.resource_filename(
        base_package, os.path.join("testdata", "cert.pem"))

    cert1_path = pkg_resources.resource_filename(
        base_package, os.path.join("testdata", "cert-san.pem"))

    cert0 = Cert(cert0_path)
    cert1 = Cert(cert1_path)

    key_path = pkg_resources.resource_filename(
        base_package, os.path.join("testdata", "rsa512_key.pem"))

    return [cert0_path, cert1_path], [cert0, cert1], key_path


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
