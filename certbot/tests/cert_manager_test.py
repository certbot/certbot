"""Tests for certbot.cert_manager."""
# pylint disable=protected-access
import os
import shutil
import tempfile
import unittest

import configobj
import mock

from certbot import configuration
from certbot import errors

from certbot.display import util as display_util
from certbot.storage import ALL_FOUR

from certbot.tests import storage_test
from certbot.tests import util as test_util

class BaseCertManagerTest(unittest.TestCase):
    """Base class for setting up Cert Manager tests.
    """
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

        os.makedirs(os.path.join(self.tempdir, "renewal"))

        self.cli_config = configuration.NamespaceConfig(mock.MagicMock(
            config_dir=self.tempdir,
            work_dir=self.tempdir,
            logs_dir=self.tempdir,
            quiet=False,
        ))

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
        # TODO: maybe provide NamespaceConfig.make_dirs?
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


class UpdateLiveSymlinksTest(BaseCertManagerTest):
    """Tests for certbot.cert_manager.update_live_symlinks
    """
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
            archive_paths[domain] = dict((kind,
                os.path.join(archive_dir_path, kind + "1.pem")) for kind in ALL_FOUR)
            for kind in ALL_FOUR:
                live_path = self.configs[domain][kind]
                archive_path = archive_paths[domain][kind]
                open(archive_path, 'a').close()
                # path is incorrect but base must be correct
                os.symlink(os.path.join(self.tempdir, kind + "1.pem"), live_path)

        # run update symlinks
        cert_manager.update_live_symlinks(self.cli_config)

        # check that symlinks go where they should
        prev_dir = os.getcwd()
        try:
            for domain in self.domains:
                for kind in ALL_FOUR:
                    os.chdir(os.path.dirname(self.configs[domain][kind]))
                    self.assertEqual(
                        os.path.realpath(os.readlink(self.configs[domain][kind])),
                        os.path.realpath(archive_paths[domain][kind]))
        finally:
            os.chdir(prev_dir)


class DeleteTest(storage_test.BaseRenewableCertTest):
    """Tests for certbot.cert_manager.delete
    """
    @mock.patch('zope.component.getUtility')
    @mock.patch('certbot.cert_manager.lineage_for_certname')
    @mock.patch('certbot.storage.delete_files')
    def test_delete(self, mock_delete_files, mock_lineage_for_certname, unused_get_utility):
        """Test delete"""
        mock_lineage_for_certname.return_value = self.test_rc
        self.cli_config.certname = "example.org"
        from certbot import cert_manager
        cert_manager.delete(self.cli_config)
        self.assertTrue(mock_delete_files.called)


class CertificatesTest(BaseCertManagerTest):
    """Tests for certbot.cert_manager.certificates
    """
    def _certificates(self, *args, **kwargs):
        from certbot.cert_manager import certificates
        return certificates(*args, **kwargs)

    @mock.patch('certbot.cert_manager.logger')
    @mock.patch('zope.component.getUtility')
    def test_certificates_parse_fail(self, mock_utility, mock_logger):
        self._certificates(self.cli_config)
        self.assertTrue(mock_logger.warning.called) #pylint: disable=no-member
        self.assertTrue(mock_utility.called)

    @mock.patch('certbot.cert_manager.logger')
    @mock.patch('zope.component.getUtility')
    def test_certificates_quiet(self, mock_utility, mock_logger):
        self.cli_config.quiet = True
        self._certificates(self.cli_config)
        self.assertFalse(mock_utility.notification.called)
        self.assertTrue(mock_logger.warning.called) #pylint: disable=no-member

    @mock.patch('certbot.cert_manager.logger')
    @mock.patch('zope.component.getUtility')
    @mock.patch("certbot.storage.RenewableCert")
    @mock.patch('certbot.cert_manager._report_human_readable')
    def test_certificates_parse_success(self, mock_report, mock_renewable_cert,
        mock_utility, mock_logger):
        mock_report.return_value = ""
        self._certificates(self.cli_config)
        self.assertFalse(mock_logger.warning.called) #pylint: disable=no-member
        self.assertTrue(mock_report.called)
        self.assertTrue(mock_utility.called)
        self.assertTrue(mock_renewable_cert.called)

    @mock.patch('certbot.cert_manager.logger')
    @mock.patch('zope.component.getUtility')
    def test_certificates_no_files(self, mock_utility, mock_logger):
        tempdir = tempfile.mkdtemp()

        cli_config = configuration.NamespaceConfig(mock.MagicMock(
                config_dir=tempdir,
                work_dir=tempdir,
                logs_dir=tempdir,
                quiet=False,
        ))

        os.makedirs(os.path.join(tempdir, "renewal"))
        self._certificates(cli_config)
        self.assertFalse(mock_logger.warning.called) #pylint: disable=no-member
        self.assertTrue(mock_utility.called)
        shutil.rmtree(tempdir)

    @mock.patch('certbot.cert_manager.ocsp.RevocationChecker.ocsp_status')
    def test_report_human_readable(self, mock_ocsp):
        mock_ocsp.side_effect = lambda _cert, _chain, status: status
        from certbot import cert_manager
        import datetime, pytz
        expiry = pytz.UTC.fromutc(datetime.datetime.utcnow())

        cert = mock.MagicMock(lineagename="nameone")
        cert.target_expiry = expiry
        cert.names.return_value = ["nameone", "nametwo"]
        cert.is_test_cert = False
        parsed_certs = [cert]

        mock_config = mock.MagicMock(certname=None, lineagename=None)
        # pylint: disable=protected-access
        out = cert_manager._report_human_readable(mock_config, parsed_certs)
        self.assertTrue("INVALID: EXPIRED" in out)

        cert.target_expiry += datetime.timedelta(hours=2)
        # pylint: disable=protected-access
        out = cert_manager._report_human_readable(mock_config, parsed_certs)
        self.assertTrue('1 hour(s)' in out)
        self.assertTrue('VALID' in out and not 'INVALID' in out)

        cert.target_expiry += datetime.timedelta(days=1)
        # pylint: disable=protected-access
        out = cert_manager._report_human_readable(mock_config, parsed_certs)
        self.assertTrue('1 day' in out)
        self.assertFalse('under' in out)
        self.assertTrue('VALID' in out and not 'INVALID' in out)

        cert.target_expiry += datetime.timedelta(days=2)
        # pylint: disable=protected-access
        out = cert_manager._report_human_readable(mock_config, parsed_certs)
        self.assertTrue('3 days' in out)
        self.assertTrue('VALID' in out and not 'INVALID' in out)

        cert.is_test_cert = True
        out = cert_manager._report_human_readable(mock_config, parsed_certs)
        self.assertTrue('INVALID: TEST_CERT' in out)


class SearchLineagesTest(BaseCertManagerTest):
    """Tests for certbot.cert_manager._search_lineages."""

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot.storage.renewal_conf_files')
    @mock.patch('certbot.storage.RenewableCert')
    def test_cert_storage_error(self, mock_renewable_cert, mock_renewal_conf_files,
        mock_make_or_verify_dir):
        mock_renewal_conf_files.return_value = ["badfile"]
        mock_renewable_cert.side_effect = errors.CertStorageError
        from certbot import cert_manager
        # pylint: disable=protected-access
        self.assertEqual(cert_manager._search_lineages(self.cli_config, lambda x: x, "check"),
            "check")
        self.assertTrue(mock_make_or_verify_dir.called)


class LineageForCertnameTest(BaseCertManagerTest):
    """Tests for certbot.cert_manager.lineage_for_certname"""

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot.storage.renewal_conf_files')
    @mock.patch('certbot.storage.RenewableCert')
    def test_found_match(self, mock_renewable_cert, mock_renewal_conf_files,
        mock_make_or_verify_dir):
        mock_renewal_conf_files.return_value = ["somefile.conf"]
        mock_match = mock.Mock(lineagename="example.com")
        mock_renewable_cert.return_value = mock_match
        from certbot import cert_manager
        self.assertEqual(cert_manager.lineage_for_certname(self.cli_config, "example.com"),
            mock_match)
        self.assertTrue(mock_make_or_verify_dir.called)

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot.storage.renewal_conf_files')
    @mock.patch('certbot.storage.RenewableCert')
    def test_no_match(self, mock_renewable_cert, mock_renewal_conf_files,
        mock_make_or_verify_dir):
        mock_renewal_conf_files.return_value = ["somefile.conf"]
        mock_match = mock.Mock(lineagename="other.com")
        mock_renewable_cert.return_value = mock_match
        from certbot import cert_manager
        self.assertEqual(cert_manager.lineage_for_certname(self.cli_config, "example.com"),
            None)
        self.assertTrue(mock_make_or_verify_dir.called)


class DomainsForCertnameTest(BaseCertManagerTest):
    """Tests for certbot.cert_manager.domains_for_certname"""

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot.storage.renewal_conf_files')
    @mock.patch('certbot.storage.RenewableCert')
    def test_found_match(self, mock_renewable_cert, mock_renewal_conf_files,
        mock_make_or_verify_dir):
        mock_renewal_conf_files.return_value = ["somefile.conf"]
        mock_match = mock.Mock(lineagename="example.com")
        domains = ["example.com", "example.org"]
        mock_match.names.return_value = domains
        mock_renewable_cert.return_value = mock_match
        from certbot import cert_manager
        self.assertEqual(cert_manager.domains_for_certname(self.cli_config, "example.com"),
            domains)
        self.assertTrue(mock_make_or_verify_dir.called)

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot.storage.renewal_conf_files')
    @mock.patch('certbot.storage.RenewableCert')
    def test_no_match(self, mock_renewable_cert, mock_renewal_conf_files,
        mock_make_or_verify_dir):
        mock_renewal_conf_files.return_value = ["somefile.conf"]
        mock_match = mock.Mock(lineagename="example.com")
        domains = ["example.com", "example.org"]
        mock_match.names.return_value = domains
        mock_renewable_cert.return_value = mock_match
        from certbot import cert_manager
        self.assertEqual(cert_manager.domains_for_certname(self.cli_config, "other.com"),
            None)
        self.assertTrue(mock_make_or_verify_dir.called)


class RenameLineageTest(BaseCertManagerTest):
    """Tests for certbot.cert_manager.rename_lineage"""

    def setUp(self):
        super(RenameLineageTest, self).setUp()
        self.mock_config = configuration.NamespaceConfig(
            namespace=mock.MagicMock(
                config_dir=self.tempdir,
                work_dir=self.tempdir,
                logs_dir=self.tempdir,
                certname="example.org",
                new_certname="after",
            )
        )

    def _call(self, *args, **kwargs):
        from certbot import cert_manager
        return cert_manager.rename_lineage(*args, **kwargs)

    @mock.patch('certbot.storage.renewal_conf_files')
    @mock.patch('certbot.main.zope.component.getUtility')
    def test_no_certname(self, mock_get_utility, mock_renewal_conf_files):
        mock_config = mock.Mock(certname=None, new_certname="two")

        # if not choices
        mock_renewal_conf_files.return_value = []
        self.assertRaises(errors.Error, self._call, mock_config)

        mock_renewal_conf_files.return_value = ["one.conf"]
        util_mock = mock.Mock()
        util_mock.menu.return_value = (display_util.CANCEL, 0)
        mock_get_utility.return_value = util_mock
        self.assertRaises(errors.Error, self._call, mock_config)

        util_mock.menu.return_value = (display_util.OK, -1)
        self.assertRaises(errors.Error, self._call, mock_config)

    @mock.patch('certbot.main.zope.component.getUtility')
    def test_no_new_certname(self, mock_get_utility):
        mock_config = mock.Mock(certname="one", new_certname=None)

        util_mock = mock.Mock()
        util_mock.input.return_value = (display_util.CANCEL, "name")
        mock_get_utility.return_value = util_mock
        self.assertRaises(errors.Error, self._call, mock_config)

        util_mock = mock.Mock()
        util_mock.input.return_value = (display_util.OK, None)
        mock_get_utility.return_value = util_mock
        self.assertRaises(errors.Error, self._call, mock_config)

    @mock.patch('certbot.main.zope.component.getUtility')
    @mock.patch('certbot.cert_manager.lineage_for_certname')
    def test_no_existing_certname(self, mock_lineage_for_certname, unused_get_utility):
        mock_config = mock.Mock(certname="one", new_certname="two")
        mock_lineage_for_certname.return_value = None
        self.assertRaises(errors.ConfigurationError,
            self._call, mock_config)

    @mock.patch('certbot.main.zope.component.getUtility')
    @mock.patch("certbot.storage.RenewableCert._check_symlinks")
    def test_rename_cert(self, mock_check, unused_get_utility):
        mock_check.return_value = True
        mock_config = self.mock_config
        self._call(mock_config)
        from certbot import cert_manager
        updated_lineage = cert_manager.lineage_for_certname(mock_config, mock_config.new_certname)
        self.assertTrue(updated_lineage is not None)
        self.assertEqual(updated_lineage.lineagename, mock_config.new_certname)

    @mock.patch('certbot.main.zope.component.getUtility')
    @mock.patch("certbot.storage.RenewableCert._check_symlinks")
    def test_rename_cert_interactive_certname(self, mock_check, mock_get_utility):
        mock_check.return_value = True
        mock_config = self.mock_config
        mock_config.certname = None
        util_mock = mock.Mock()
        util_mock.menu.return_value = (display_util.OK, 0)
        mock_get_utility.return_value = util_mock
        self._call(mock_config)
        from certbot import cert_manager
        updated_lineage = cert_manager.lineage_for_certname(mock_config, mock_config.new_certname)
        self.assertTrue(updated_lineage is not None)
        self.assertEqual(updated_lineage.lineagename, mock_config.new_certname)

    @mock.patch('certbot.main.zope.component.getUtility')
    @mock.patch("certbot.storage.RenewableCert._check_symlinks")
    def test_rename_cert_bad_new_certname(self, mock_check, unused_get_utility):
        mock_check.return_value = True
        mock_config = self.mock_config

        # for example, don't rename to existing certname
        mock_config.new_certname = "example.org"
        self.assertRaises(errors.ConfigurationError, self._call, mock_config)

        mock_config.new_certname = "one{0}two".format(os.path.sep)
        self.assertRaises(errors.ConfigurationError, self._call, mock_config)


class DuplicativeCertsTest(storage_test.BaseRenewableCertTest):
    """Test to avoid duplicate lineages."""

    def setUp(self):
        super(DuplicativeCertsTest, self).setUp()
        self.config.write()
        self._write_out_ex_kinds()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    @mock.patch('certbot.util.make_or_verify_dir')
    def test_find_duplicative_names(self, unused_makedir):
        from certbot.cert_manager import find_duplicative_certs
        test_cert = test_util.load_vector('cert-san.pem')
        with open(self.test_rc.cert, 'wb') as f:
            f.write(test_cert)

        # No overlap at all
        result = find_duplicative_certs(
            self.cli_config, ['wow.net', 'hooray.org'])
        self.assertEqual(result, (None, None))

        # Totally identical
        result = find_duplicative_certs(
            self.cli_config, ['example.com', 'www.example.com'])
        self.assertTrue(result[0].configfile.filename.endswith('example.org.conf'))
        self.assertEqual(result[1], None)

        # Superset
        result = find_duplicative_certs(
            self.cli_config, ['example.com', 'www.example.com', 'something.new'])
        self.assertEqual(result[0], None)
        self.assertTrue(result[1].configfile.filename.endswith('example.org.conf'))

        # Partial overlap doesn't count
        result = find_duplicative_certs(
            self.cli_config, ['example.com', 'something.new'])
        self.assertEqual(result, (None, None))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
