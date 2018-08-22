"""Test for certbot_apache.configurator OCSP Prefetching functionality"""
import dbm
import os
import unittest
import mock
# six is used in mock.patch()
import six  # pylint: disable=unused-import

from certbot_apache.tests import util


class OCSPPrefetchTest(util.ApacheTest):
    """Tests for OCSP Prefetch feature"""
    # pylint: disable=protected-access

    def setUp(self):  # pylint: disable=arguments-differ
        super(OCSPPrefetchTest, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)

        self.lineage = mock.MagicMock(cert_path="cert", chain_path="chain")
        self.config.parser.modules.add("headers_module")
        self.config.parser.modules.add("mod_headers.c")
        self.config.parser.modules.add("ssl_module")
        self.config.parser.modules.add("mod_ssl.c")
        self.config.parser.modules.add("socache_dbm_module")
        self.config.parser.modules.add("mod_socache_dbm.c")

        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def call_mocked(self, func, *args, **kwargs):
        """Helper method to call functins with mock stack"""

        ver_path = "certbot_apache.configurator.ApacheConfigurator.get_version"
        cry_path = "certbot.crypto_util.cert_sha1_fingerprint"

        with mock.patch(ver_path) as mock_ver:
            mock_ver.return_value = (2, 4, 10)
            with mock.patch(cry_path) as mock_cry:
                mock_cry.return_value = b'j\x056\x1f\xfa\x08B\xe8D\xa1Bn\xeb*A\xebWx\xdd\xfe'
                return func(*args, **kwargs)

    @mock.patch("certbot_apache.configurator.ApacheConfigurator.restart")
    @mock.patch("certbot_apache.configurator.ApacheConfigurator.enable_mod")
    def test_ocsp_prefetch_enable_mods(self, mock_enable, _restart):
        self.config.parser.modules.discard("socache_dbm_module")
        self.config.parser.modules.discard("mod_socache_dbm.c")
        self.config.parser.modules.discard("headers_module")
        self.config.parser.modules.discard("mod_header.c")

        ref_path = "certbot_apache.configurator.ApacheConfigurator._ocsp_refresh"
        with mock.patch(ref_path):
            self.call_mocked(self.config.enable_ocsp_prefetch,
                             self.lineage,
                             ["ocspvhost.com"])
        self.assertTrue(mock_enable.called)
        self.assertEquals(len(self.config._ocsp_prefetch), 1)

    @mock.patch("certbot_apache.constants.OCSP_INTERNAL_TTL", 0)
    @mock.patch("certbot_apache.configurator.ApacheConfigurator.restart")
    def test_ocsp_prefetch_refresh(self, _mock_restart):
        def ocsp_req_mock(workfile):
            """Method to mock the OCSP request and write response to file"""
            with open(workfile, 'w') as fh:
                fh.write("MOCKRESPONSE")
            return True

        ocsp_path = "certbot.ocsp.OCSPResponseHandler.ocsp_request_to_file"
        with mock.patch(ocsp_path, side_effect=ocsp_req_mock):
            self.call_mocked(self.config.enable_ocsp_prefetch,
                                self.lineage,
                                ["ocspvhost.com"])
        odbm = dbm.open(os.path.join(self.config_dir, "ocsp", "ocsp_cache"), 'c')
        self.assertEquals(len(odbm.keys()), 1)
        # The actual response data is prepended by Apache timestamp
        self.assertTrue(odbm[odbm.keys()[0]].endswith(b'MOCKRESPONSE'))
        odbm.close()

        with mock.patch(ocsp_path, side_effect=ocsp_req_mock) as mock_ocsp:
            self.call_mocked(self.config.update_ocsp_prefetch, None)
            self.assertTrue(mock_ocsp.called)

    @mock.patch("certbot_apache.configurator.ApacheConfigurator.restart")
    def test_ocsp_prefetch_refresh_noop(self, _mock_restart):
        def ocsp_req_mock(workfile):
            """Method to mock the OCSP request and write response to file"""
            with open(workfile, 'w') as fh:
                fh.write("MOCKRESPONSE")
            return True

        ocsp_path = "certbot.ocsp.OCSPResponseHandler.ocsp_request_to_file"
        with mock.patch(ocsp_path, side_effect=ocsp_req_mock):
            self.call_mocked(self.config.enable_ocsp_prefetch,
                                self.lineage,
                                ["ocspvhost.com"])
        self.assertEquals(len(self.config._ocsp_prefetch), 1)
        refresh_path = "certbot_apache.configurator.ApacheConfigurator._ocsp_refresh"
        with mock.patch(refresh_path) as mock_refresh:
            self.call_mocked(self.config.update_ocsp_prefetch, None)
            self.assertFalse(mock_refresh.called)

    @mock.patch("certbot_apache.configurator.ApacheConfigurator.config_test")
    def test_ocsp_prefetch_backup_db(self, _mock_test):
        db_path = os.path.join(self.config_dir, "ocsp", "ocsp_cache.db")
        def ocsp_del_db():
            """Side effect of _reload() that deletes the DBM file, like Apache
            does when restarting"""
            os.remove(db_path)
            self.assertFalse(os.path.isfile(db_path))

        self.config._ensure_ocsp_dirs()
        odbm = dbm.open(db_path[:-3], 'c')
        odbm["mock_key"] = b'mock_value'
        odbm.close()

        # Mock OCSP prefetch dict to signify that there should be a db
        self.config._ocsp_prefetch = {"mock": "value"}
        rel_path = "certbot_apache.configurator.ApacheConfigurator._reload"
        with mock.patch(rel_path, side_effect=ocsp_del_db) as mock_reload:
            self.config.restart()

        odbm = dbm.open(db_path[:-3], 'c')
        self.assertEquals(odbm["mock_key"], b'mock_value')
        odbm.close()

    @mock.patch("certbot_apache.configurator.ApacheConfigurator.config_test")
    @mock.patch("certbot_apache.configurator.ApacheConfigurator._reload")
    def test_ocsp_prefetch_backup_db_error(self, _mock_reload, _mock_test):
        self.config._ensure_ocsp_dirs()
        log_path = "certbot_apache.configurator.logger.debug"
        log_string = "Encountered an issue while trying to backup OCSP dbm file"
        log_string2 = "Encountered an issue when trying to restore OCSP dbm file"
        self.config._ocsp_prefetch = {"mock": "value"}
        with mock.patch("shutil.copy2", side_effect=IOError):
            with mock.patch(log_path) as mock_log:
                self.config.restart()
                self.assertTrue(mock_log.called)
                self.assertEquals(mock_log.call_count, 2)
                self.assertTrue(log_string in mock_log.call_args_list[0][0][0])
                self.assertTrue(log_string2 in mock_log.call_args_list[1][0][0])

    @mock.patch("certbot_apache.configurator.ApacheConfigurator.restart")
    def test_ocsp_prefetch_refresh_fail(self, _mock_restart):
        ocsp_path = "certbot.ocsp.OCSPResponseHandler.ocsp_request_to_file"
        log_path = "certbot_apache.configurator.logger.warning"
        with mock.patch(ocsp_path) as mock_ocsp:
            mock_ocsp.return_value = False
            with mock.patch(log_path) as mock_log:
                self.call_mocked(self.config.enable_ocsp_prefetch,
                                self.lineage,
                                ["ocspvhost.com"])
                self.assertTrue(mock_log.called)
                self.assertTrue(
                    "trying to prefetch OCSP" in mock_log.call_args[0][0])

    @mock.patch("certbot_apache.configurator.ApacheConfigurator._ocsp_refresh_if_needed")
    def test_ocsp_prefetch_update_noop(self, mock_refresh):
        self.config.update_ocsp_prefetch(None)
        self.assertFalse(mock_refresh.called)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
