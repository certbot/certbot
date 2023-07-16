
"""Tests for certbot._internal.cert_manager."""
# pylint: disable=protected-access
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import configobj
import pytest

from certbot import configuration
from certbot import errors
from certbot._internal.storage import ALL_FOUR
from certbot._internal.tests import storage_test
from certbot.compat import filesystem
from certbot.compat import os
from certbot.display import util as display_util
from certbot.tests import util as test_util


class BaseCertManagerTest(test_util.ConfigTestCase):
    """Base class for setting up Cert Manager tests.
    """
    def setUp(self):
        super().setUp()

        self.config.quiet = False
        filesystem.makedirs(self.config.renewal_configs_dir)

        self.domains = {
            "example.org": None,
            "other.com": os.path.join(self.config.config_dir, "specialarchive")
        }
        self.config_files = {domain: self._set_up_config(domain, self.domains[domain])
            for domain in self.domains}

        # We also create a file that isn't a renewal config in the same
        # location to test that logic that reads in all-and-only renewal
        # configs will ignore it and NOT attempt to parse it.
        with open(os.path.join(self.config.renewal_configs_dir, "IGNORE.THIS"), "w") as junk:
            junk.write("This file should be ignored!")

    def _set_up_config(self, domain, custom_archive):
        # TODO: maybe provide NamespaceConfig.make_dirs?
        # TODO: main() should create those dirs, c.f. #902
        filesystem.makedirs(os.path.join(self.config.live_dir, domain))
        config_file = configobj.ConfigObj()

        if custom_archive is not None:
            filesystem.makedirs(custom_archive)
            config_file["archive_dir"] = custom_archive
        else:
            filesystem.makedirs(os.path.join(self.config.default_archive_dir, domain))

        for kind in ALL_FOUR:
            config_file[kind] = os.path.join(self.config.live_dir, domain,
                                        kind + ".pem")

        config_file.filename = os.path.join(self.config.renewal_configs_dir,
                                       domain + ".conf")
        config_file.write()
        return config_file


class UpdateLiveSymlinksTest(BaseCertManagerTest):
    """Tests for certbot._internal.cert_manager.update_live_symlinks
    """
    def test_update_live_symlinks(self):
        """Test update_live_symlinks"""
        # create files with incorrect symlinks
        from certbot._internal import cert_manager
        archive_paths = {}
        for domain in self.domains:
            custom_archive = self.domains[domain]
            if custom_archive is not None:
                archive_dir_path = custom_archive
            else:
                archive_dir_path = os.path.join(self.config.default_archive_dir, domain)
            archive_paths[domain] = {kind:
                os.path.join(archive_dir_path, kind + "1.pem") for kind in ALL_FOUR}
            for kind in ALL_FOUR:
                live_path = self.config_files[domain][kind]
                archive_path = archive_paths[domain][kind]
                open(archive_path, 'a').close()
                # path is incorrect but base must be correct
                os.symlink(os.path.join(self.config.config_dir, kind + "1.pem"), live_path)

        # run update symlinks
        cert_manager.update_live_symlinks(self.config)

        # check that symlinks go where they should
        prev_dir = os.getcwd()
        try:
            for domain in self.domains:
                for kind in ALL_FOUR:
                    os.chdir(os.path.dirname(self.config_files[domain][kind]))
                    assert filesystem.realpath(filesystem.readlink(self.config_files[domain][kind])) == \
                        filesystem.realpath(archive_paths[domain][kind])
        finally:
            os.chdir(prev_dir)


class DeleteTest(storage_test.BaseRenewableCertTest):
    """Tests for certbot._internal.cert_manager.delete
    """

    def _call(self):
        from certbot._internal import cert_manager
        cert_manager.delete(self.config)

    @test_util.patch_display_util()
    @mock.patch('certbot.display.util.notify')
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.storage.delete_files')
    def test_delete_from_config_yes(self, mock_delete_files, mock_lineage_for_certname,
        mock_notify, mock_util):
        """Test delete"""
        mock_lineage_for_certname.return_value = self.test_rc
        mock_util().yesno.return_value = True
        self.config.certname = "example.org"
        self._call()
        mock_delete_files.assert_called_once_with(self.config, "example.org")
        mock_notify.assert_called_once_with(
            "Deleted all files relating to certificate example.org."
        )

    @test_util.patch_display_util()
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.storage.delete_files')
    def test_delete_from_config_no(self, mock_delete_files, mock_lineage_for_certname,
        mock_util):
        """Test delete"""
        mock_lineage_for_certname.return_value = self.test_rc
        mock_util().yesno.return_value = False
        self.config.certname = "example.org"
        self._call()
        assert mock_delete_files.call_count == 0

    @test_util.patch_display_util()
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.storage.delete_files')
    def test_delete_interactive_single_yes(self, mock_delete_files, mock_lineage_for_certname,
        mock_util):
        """Test delete"""
        mock_lineage_for_certname.return_value = self.test_rc
        mock_util().checklist.return_value = (display_util.OK, ["example.org"])
        mock_util().yesno.return_value = True
        self._call()
        mock_delete_files.assert_called_once_with(self.config, "example.org")

    @test_util.patch_display_util()
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.storage.delete_files')
    def test_delete_interactive_single_no(self, mock_delete_files, mock_lineage_for_certname,
        mock_util):
        """Test delete"""
        mock_lineage_for_certname.return_value = self.test_rc
        mock_util().checklist.return_value = (display_util.OK, ["example.org"])
        mock_util().yesno.return_value = False
        self._call()
        assert mock_delete_files.call_count == 0

    @test_util.patch_display_util()
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.storage.delete_files')
    def test_delete_interactive_multiple_yes(self, mock_delete_files, mock_lineage_for_certname,
        mock_util):
        """Test delete"""
        mock_lineage_for_certname.return_value = self.test_rc
        mock_util().checklist.return_value = (display_util.OK, ["example.org", "other.org"])
        mock_util().yesno.return_value = True
        self._call()
        mock_delete_files.assert_any_call(self.config, "example.org")
        mock_delete_files.assert_any_call(self.config, "other.org")
        assert mock_delete_files.call_count == 2

    @test_util.patch_display_util()
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    @mock.patch('certbot._internal.storage.delete_files')
    def test_delete_interactive_multiple_no(self, mock_delete_files, mock_lineage_for_certname,
        mock_util):
        """Test delete"""
        mock_lineage_for_certname.return_value = self.test_rc
        mock_util().checklist.return_value = (display_util.OK, ["example.org", "other.org"])
        mock_util().yesno.return_value = False
        self._call()
        assert mock_delete_files.call_count == 0


class CertificatesTest(BaseCertManagerTest):
    """Tests for certbot._internal.cert_manager.certificates
    """
    def _certificates(self, *args, **kwargs):
        from certbot._internal.cert_manager import certificates
        return certificates(*args, **kwargs)

    @mock.patch('certbot._internal.cert_manager.logger')
    @test_util.patch_display_util()
    def test_certificates_parse_fail(self, mock_utility, mock_logger):
        self._certificates(self.config)
        assert mock_logger.warning.called #pylint: disable=no-member
        assert mock_utility.called

    @mock.patch('certbot._internal.cert_manager.logger')
    @test_util.patch_display_util()
    def test_certificates_quiet(self, mock_utility, mock_logger):
        self.config.quiet = True
        self._certificates(self.config)
        assert mock_utility.notification.called is False
        assert mock_logger.warning.called #pylint: disable=no-member

    @mock.patch('certbot.crypto_util.verify_renewable_cert')
    @mock.patch('certbot._internal.cert_manager.logger')
    @test_util.patch_display_util()
    @mock.patch("certbot._internal.storage.RenewableCert")
    @mock.patch('certbot._internal.cert_manager._report_human_readable')
    def test_certificates_parse_success(self, mock_report, mock_renewable_cert,
        mock_utility, mock_logger, mock_verifier):
        mock_verifier.return_value = None
        mock_report.return_value = ""
        self._certificates(self.config)
        assert mock_logger.warning.called is False
        assert mock_report.called
        assert mock_utility.called
        assert mock_renewable_cert.called

    @mock.patch('certbot._internal.cert_manager.logger')
    @test_util.patch_display_util()
    def test_certificates_no_files(self, mock_utility, mock_logger):
        empty_tempdir = tempfile.mkdtemp()
        empty_config = configuration.NamespaceConfig(mock.MagicMock(
            config_dir=os.path.join(empty_tempdir, "config"),
            work_dir=os.path.join(empty_tempdir, "work"),
            logs_dir=os.path.join(empty_tempdir, "logs"),
            quiet=False
        ))

        filesystem.makedirs(empty_config.renewal_configs_dir)
        self._certificates(empty_config)
        assert mock_logger.warning.called is False
        assert mock_utility.called
        shutil.rmtree(empty_tempdir)

    @mock.patch('certbot.crypto_util.get_serial_from_cert')
    @mock.patch('certbot._internal.cert_manager.ocsp.RevocationChecker.ocsp_revoked')
    def test_report_human_readable(self, mock_revoked, mock_serial):
        mock_revoked.return_value = None
        mock_serial.return_value = 1234567890
        import datetime

        import pytz

        from certbot._internal import cert_manager
        expiry = datetime.datetime.now(pytz.UTC)

        cert = mock.MagicMock(lineagename="nameone")
        cert.target_expiry = expiry
        cert.names.return_value = ["nameone", "nametwo"]
        cert.is_test_cert = False
        parsed_certs = [cert]

        mock_config = mock.MagicMock(certname=None, lineagename=None)
        # pylint: disable=protected-access

        # pylint: disable=protected-access
        get_report = lambda: cert_manager._report_human_readable(mock_config, parsed_certs)

        out = get_report()
        assert "INVALID: EXPIRED" in out

        cert.target_expiry += datetime.timedelta(hours=2)
        # pylint: disable=protected-access
        out = get_report()
        assert ('1 hour' in out or '2 hour(s)' in out) is True
        assert 'VALID' in out
        assert 'INVALID' not in out

        cert.target_expiry += datetime.timedelta(days=1)
        # pylint: disable=protected-access
        out = get_report()
        assert '1 day' in out
        assert 'under' not in out
        assert 'VALID' in out
        assert 'INVALID' not in out

        cert.target_expiry += datetime.timedelta(days=2)
        # pylint: disable=protected-access
        out = get_report()
        assert '3 days' in out
        assert 'VALID' in out
        assert 'INVALID' not in out

        cert.is_test_cert = True
        mock_revoked.return_value = True
        out = get_report()
        assert 'INVALID: TEST_CERT, REVOKED' in out

        cert = mock.MagicMock(lineagename="indescribable")
        cert.target_expiry = expiry
        cert.names.return_value = ["nameone", "thrice.named"]
        cert.is_test_cert = True
        parsed_certs.append(cert)

        out = get_report()
        assert len(re.findall("INVALID:", out)) == 2
        mock_config.domains = ["thrice.named"]
        out = get_report()
        assert len(re.findall("INVALID:", out)) == 1
        mock_config.domains = ["nameone"]
        out = get_report()
        assert len(re.findall("INVALID:", out)) == 2
        mock_config.certname = "indescribable"
        out = get_report()
        assert len(re.findall("INVALID:", out)) == 1
        mock_config.certname = "horror"
        out = get_report()
        assert len(re.findall("INVALID:", out)) == 0


class SearchLineagesTest(BaseCertManagerTest):
    """Tests for certbot._internal.cert_manager._search_lineages."""

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @mock.patch('certbot._internal.storage.RenewableCert')
    def test_cert_storage_error(self, mock_renewable_cert, mock_renewal_conf_files,
                                mock_make_or_verify_dir):
        mock_renewal_conf_files.return_value = ["badfile"]
        mock_renewable_cert.side_effect = errors.CertStorageError
        from certbot._internal import cert_manager

        # pylint: disable=protected-access
        assert cert_manager._search_lineages(self.config, lambda x: x, "check") == "check"
        assert mock_make_or_verify_dir.called


class LineageForCertnameTest(BaseCertManagerTest):
    """Tests for certbot._internal.cert_manager.lineage_for_certname"""

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    @mock.patch('certbot._internal.storage.RenewableCert')
    def test_found_match(self, mock_renewable_cert, mock_renewal_conf_file,
                         mock_make_or_verify_dir):
        mock_renewal_conf_file.return_value = "somefile.conf"
        mock_match = mock.Mock(lineagename="example.com")
        mock_renewable_cert.return_value = mock_match
        from certbot._internal import cert_manager
        assert cert_manager.lineage_for_certname(self.config, "example.com") == mock_match
        assert mock_make_or_verify_dir.called

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    def test_no_match(self, mock_renewal_conf_file, mock_make_or_verify_dir):
        mock_renewal_conf_file.return_value = "other.com.conf"
        from certbot._internal import cert_manager
        assert cert_manager.lineage_for_certname(self.config, "example.com") is None
        assert mock_make_or_verify_dir.called

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    def test_no_renewal_file(self, mock_renewal_conf_file, mock_make_or_verify_dir):
        mock_renewal_conf_file.side_effect = errors.CertStorageError()
        from certbot._internal import cert_manager
        assert cert_manager.lineage_for_certname(self.config, "example.com") is None
        assert mock_make_or_verify_dir.called


class DomainsForCertnameTest(BaseCertManagerTest):
    """Tests for certbot._internal.cert_manager.domains_for_certname"""

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    @mock.patch('certbot._internal.storage.RenewableCert')
    def test_found_match(self, mock_renewable_cert, mock_renewal_conf_file,
                         mock_make_or_verify_dir):
        mock_renewal_conf_file.return_value = "somefile.conf"
        mock_match = mock.Mock(lineagename="example.com")
        domains = ["example.com", "example.org"]
        mock_match.names.return_value = domains
        mock_renewable_cert.return_value = mock_match
        from certbot._internal import cert_manager
        assert cert_manager.domains_for_certname(self.config, "example.com") == \
            domains
        assert mock_make_or_verify_dir.called

    @mock.patch('certbot.util.make_or_verify_dir')
    @mock.patch('certbot._internal.storage.renewal_file_for_certname')
    def test_no_match(self, mock_renewal_conf_file, mock_make_or_verify_dir):
        mock_renewal_conf_file.return_value = "somefile.conf"
        from certbot._internal import cert_manager
        assert cert_manager.domains_for_certname(self.config, "other.com") is None
        assert mock_make_or_verify_dir.called


class RenameLineageTest(BaseCertManagerTest):
    """Tests for certbot._internal.cert_manager.rename_lineage"""

    def setUp(self):
        super().setUp()
        self.config.certname = "example.org"
        self.config.new_certname = "after"

    def _call(self, *args, **kwargs):
        from certbot._internal import cert_manager
        return cert_manager.rename_lineage(*args, **kwargs)

    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @test_util.patch_display_util()
    def test_no_certname(self, mock_get_utility, mock_renewal_conf_files):
        self.config.certname = None
        self.config.new_certname = "two"

        # if not choices
        mock_renewal_conf_files.return_value = []
        with pytest.raises(errors.Error):
            self._call(self.config)

        mock_renewal_conf_files.return_value = ["one.conf"]
        util_mock = mock_get_utility()
        util_mock.menu.return_value = (display_util.CANCEL, 0)
        with pytest.raises(errors.Error):
            self._call(self.config)

        util_mock.menu.return_value = (display_util.OK, -1)
        with pytest.raises(errors.Error):
            self._call(self.config)

    @test_util.patch_display_util()
    def test_no_new_certname(self, mock_get_utility):
        self.config.certname = "one"
        self.config.new_certname = None

        util_mock = mock_get_utility()
        util_mock.input.return_value = (display_util.CANCEL, "name")
        with pytest.raises(errors.Error):
            self._call(self.config)

        util_mock.input.return_value = (display_util.OK, None)
        with pytest.raises(errors.Error):
            self._call(self.config)

    @test_util.patch_display_util()
    @mock.patch('certbot._internal.cert_manager.lineage_for_certname')
    def test_no_existing_certname(self, mock_lineage_for_certname, unused_get_utility):
        self.config.certname = "one"
        self.config.new_certname = "two"
        mock_lineage_for_certname.return_value = None
        with pytest.raises(errors.ConfigurationError):
            self._call(self.config)

    @test_util.patch_display_util()
    @mock.patch("certbot._internal.storage.RenewableCert._check_symlinks")
    def test_rename_cert(self, mock_check, unused_get_utility):
        mock_check.return_value = True
        self._call(self.config)
        from certbot._internal import cert_manager
        updated_lineage = cert_manager.lineage_for_certname(self.config, self.config.new_certname)
        assert updated_lineage is not None
        assert updated_lineage.lineagename == self.config.new_certname

    @test_util.patch_display_util()
    @mock.patch("certbot._internal.storage.RenewableCert._check_symlinks")
    def test_rename_cert_interactive_certname(self, mock_check, mock_get_utility):
        mock_check.return_value = True
        self.config.certname = None
        util_mock = mock_get_utility()
        util_mock.menu.return_value = (display_util.OK, 0)
        self._call(self.config)
        from certbot._internal import cert_manager
        updated_lineage = cert_manager.lineage_for_certname(self.config, self.config.new_certname)
        assert updated_lineage is not None
        assert updated_lineage.lineagename == self.config.new_certname

    @test_util.patch_display_util()
    @mock.patch("certbot._internal.storage.RenewableCert._check_symlinks")
    def test_rename_cert_bad_new_certname(self, mock_check, unused_get_utility):
        mock_check.return_value = True

        # for example, don't rename to existing certname
        self.config.new_certname = "example.org"
        with pytest.raises(errors.ConfigurationError):
            self._call(self.config)

        self.config.new_certname = "one{0}two".format(os.path.sep)
        with pytest.raises(errors.ConfigurationError):
            self._call(self.config)


class DuplicativeCertsTest(storage_test.BaseRenewableCertTest):
    """Test to avoid duplicate lineages."""

    def setUp(self):
        super().setUp()
        self.config_file.write()
        self._write_out_ex_kinds()

    @mock.patch('certbot.util.make_or_verify_dir')
    def test_find_duplicative_names(self, unused_makedir):
        from certbot._internal.cert_manager import find_duplicative_certs
        test_cert = test_util.load_vector('cert-san_512.pem')
        with open(self.test_rc.cert, 'wb') as f:
            f.write(test_cert)

        # No overlap at all
        result = find_duplicative_certs(
            self.config, ['wow.net', 'hooray.org'])
        assert result == (None, None)

        # Totally identical
        result = find_duplicative_certs(
            self.config, ['example.com', 'www.example.com'])
        assert result[0].configfile.filename.endswith('example.org.conf')
        assert result[1] is None

        # Superset
        result = find_duplicative_certs(
            self.config, ['example.com', 'www.example.com', 'something.new'])
        assert result[0] is None
        assert result[1].configfile.filename.endswith('example.org.conf')

        # Partial overlap doesn't count
        result = find_duplicative_certs(
            self.config, ['example.com', 'something.new'])
        assert result == (None, None)


class CertPathToLineageTest(storage_test.BaseRenewableCertTest):
    """Tests for certbot._internal.cert_manager.cert_path_to_lineage"""

    def setUp(self):
        super().setUp()
        self.config_file.write()
        self._write_out_ex_kinds()
        self.fullchain = os.path.join(self.config.config_dir, 'live', 'example.org',
                'fullchain.pem')
        self.config.cert_path = self.fullchain

    def _call(self, cli_config):
        from certbot._internal.cert_manager import cert_path_to_lineage
        return cert_path_to_lineage(cli_config)

    def _archive_files(self, cli_config, filetype):
        from certbot._internal.cert_manager import _archive_files
        return _archive_files(cli_config, filetype)

    def test_basic_match(self):
        assert 'example.org' == self._call(self.config)

    def test_no_match_exists(self):
        bad_test_config = self.config
        bad_test_config.cert_path = os.path.join(self.config.config_dir, 'live',
                'SailorMoon', 'fullchain.pem')
        with pytest.raises(errors.Error):
            self._call(bad_test_config)

    @mock.patch('certbot._internal.cert_manager._acceptable_matches')
    def test_options_fullchain(self, mock_acceptable_matches):
        mock_acceptable_matches.return_value = [lambda x: x.fullchain_path]
        self.config.fullchain_path = self.fullchain
        assert 'example.org' == self._call(self.config)

    @mock.patch('certbot._internal.cert_manager._acceptable_matches')
    def test_options_cert_path(self, mock_acceptable_matches):
        mock_acceptable_matches.return_value = [lambda x: x.cert_path]
        test_cert_path = os.path.join(self.config.config_dir, 'live', 'example.org',
                'cert.pem')
        self.config.cert_path = test_cert_path
        assert 'example.org' == self._call(self.config)

    @mock.patch('certbot._internal.cert_manager._acceptable_matches')
    def test_options_archive_cert(self, mock_acceptable_matches):
        # Also this and the next test check that the regex of _archive_files is working.
        self.config.cert_path = os.path.join(self.config.config_dir, 'archive', 'example.org',
            'cert11.pem')
        mock_acceptable_matches.return_value = [lambda x: self._archive_files(x, 'cert')]
        assert 'example.org' == self._call(self.config)

    @mock.patch('certbot._internal.cert_manager._acceptable_matches')
    def test_options_archive_fullchain(self, mock_acceptable_matches):
        self.config.cert_path = os.path.join(self.config.config_dir, 'archive',
            'example.org', 'fullchain11.pem')
        mock_acceptable_matches.return_value = [lambda x:
                self._archive_files(x, 'fullchain')]
        assert 'example.org' == self._call(self.config)

    def test_only_path(self):
        self.config.cert_path = self.fullchain
        assert 'example.org' == self._call(self.config)


class MatchAndCheckOverlaps(storage_test.BaseRenewableCertTest):
    """Tests for certbot._internal.cert_manager.match_and_check_overlaps w/o overlapping
       archive dirs."""
    # A test with real overlapping archive dirs can be found in tests/boulder_integration.sh
    def setUp(self):
        super().setUp()
        self.config_file.write()
        self._write_out_ex_kinds()
        self.fullchain = os.path.join(self.config.config_dir, 'live', 'example.org',
                'fullchain.pem')
        self.config.cert_path = self.fullchain

    def _call(self, cli_config, acceptable_matches, match_func, rv_func):
        from certbot._internal.cert_manager import match_and_check_overlaps
        return match_and_check_overlaps(cli_config, acceptable_matches, match_func, rv_func)

    def test_basic_match(self):
        from certbot._internal.cert_manager import _acceptable_matches
        assert ['example.org'] == self._call(self.config, _acceptable_matches(),
            lambda x: self.config.cert_path, lambda x: x.lineagename)

    @mock.patch('certbot._internal.cert_manager._search_lineages')
    def test_no_matches(self, mock_search_lineages):
        mock_search_lineages.return_value = []
        with pytest.raises(errors.Error):
            self._call(self.config, None, None, None)

    @mock.patch('certbot._internal.cert_manager._search_lineages')
    def test_too_many_matches(self, mock_search_lineages):
        mock_search_lineages.return_value = ['spider', 'dance']
        with pytest.raises(errors.OverlappingMatchFound):
            self._call(self.config, None, None, None)


class GetCertnameTest(unittest.TestCase):
    """Tests for certbot._internal.cert_manager."""

    def setUp(self):
        get_utility_patch = test_util.patch_display_util()
        self.mock_get_utility = get_utility_patch.start()
        self.addCleanup(get_utility_patch.stop)
        self.config = mock.MagicMock()
        self.config.certname = None

    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @mock.patch('certbot._internal.storage.lineagename_for_filename')
    def test_get_certnames(self, mock_name, mock_files):
        mock_files.return_value = ['example.com.conf']
        mock_name.return_value = 'example.com'
        from certbot._internal import cert_manager
        prompt = "Which certificate would you"
        self.mock_get_utility().menu.return_value = (display_util.OK, 0)
        assert cert_manager.get_certnames(
                self.config, "verb", allow_multiple=False) == ['example.com']
        assert prompt in self.mock_get_utility().menu.call_args[0][0]

    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @mock.patch('certbot._internal.storage.lineagename_for_filename')
    def test_get_certnames_custom_prompt(self, mock_name, mock_files):
        mock_files.return_value = ['example.com.conf']
        mock_name.return_value = 'example.com'
        from certbot._internal import cert_manager
        prompt = "custom prompt"
        self.mock_get_utility().menu.return_value = (display_util.OK, 0)
        assert cert_manager.get_certnames(
                self.config, "verb", allow_multiple=False, custom_prompt=prompt) == \
            ['example.com']
        assert self.mock_get_utility().menu.call_args[0][0] == \
                          prompt

    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @mock.patch('certbot._internal.storage.lineagename_for_filename')
    def test_get_certnames_user_abort(self, mock_name, mock_files):
        mock_files.return_value = ['example.com.conf']
        mock_name.return_value = 'example.com'
        from certbot._internal import cert_manager
        self.mock_get_utility().menu.return_value = (display_util.CANCEL, 0)
        with pytest.raises(errors.Error):
            cert_manager.get_certnames(self.config, "erroring_anyway", allow_multiple=False)

    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @mock.patch('certbot._internal.storage.lineagename_for_filename')
    def test_get_certnames_allow_multiple(self, mock_name, mock_files):
        mock_files.return_value = ['example.com.conf']
        mock_name.return_value = 'example.com'
        from certbot._internal import cert_manager
        prompt = "Which certificate(s) would you"
        self.mock_get_utility().checklist.return_value = (display_util.OK,
                                                          ['example.com'])
        assert cert_manager.get_certnames(
                self.config, "verb", allow_multiple=True) == ['example.com']
        assert prompt in self.mock_get_utility().checklist.call_args[0][0]

    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @mock.patch('certbot._internal.storage.lineagename_for_filename')
    def test_get_certnames_allow_multiple_custom_prompt(self, mock_name, mock_files):
        mock_files.return_value = ['example.com.conf']
        mock_name.return_value = 'example.com'
        from certbot._internal import cert_manager
        prompt = "custom prompt"
        self.mock_get_utility().checklist.return_value = (display_util.OK,
                                                          ['example.com'])
        assert cert_manager.get_certnames(
                self.config, "verb", allow_multiple=True, custom_prompt=prompt) == \
            ['example.com']
        assert self.mock_get_utility().checklist.call_args[0][0] == \
            prompt

    @mock.patch('certbot._internal.storage.renewal_conf_files')
    @mock.patch('certbot._internal.storage.lineagename_for_filename')
    def test_get_certnames_allow_multiple_user_abort(self, mock_name, mock_files):
        mock_files.return_value = ['example.com.conf']
        mock_name.return_value = 'example.com'
        from certbot._internal import cert_manager
        self.mock_get_utility().checklist.return_value = (display_util.CANCEL, [])
        with pytest.raises(errors.Error):
            cert_manager.get_certnames(self.config, "erroring_anyway", allow_multiple=True)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
