"""Tests for certbot._internal.renewal"""
import copy
import datetime
import sys
import tempfile
import unittest
from unittest import mock

import pytest

from acme import challenges
from acme import errors as acme_errors
from certbot import configuration
from certbot import errors
from certbot._internal import storage
import certbot.tests.util as test_util

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509 import Certificate

def make_cert_with_lifetime(not_before: datetime.datetime, lifetime_days: int) -> bytes:
    """Return PEM of a self-signed certificate with the given notBefore and lifetime."""
    key = ec.generate_private_key(ec.SECP256R1())
    not_after=not_before + datetime.timedelta(days=lifetime_days)
    cert = x509.CertificateBuilder(
        issuer_name=x509.Name([]),
        subject_name=x509.Name([]),
        public_key=key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=not_before,
        not_valid_after=not_after,
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("example.com")]),
        critical=False,
    ).sign(
        private_key=key,
        algorithm=hashes.SHA256(),
    )
    return cert.public_bytes(serialization.Encoding.PEM)

class RenewalTest(test_util.ConfigTestCase):
    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_ancient_webroot_renewal_conf(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal-ancient.conf')
        self.config.account = None
        self.config.email = None
        self.config.webroot_path = None
        config = configuration.NamespaceConfig(self.config)
        lineage = storage.RenewableCert(rc_path, config)
        renewalparams = lineage.configuration['renewalparams']
        # pylint: disable=protected-access
        from certbot._internal import renewal
        renewal._restore_webroot_config(config, renewalparams)
        assert config.webroot_path == ['/var/www/']

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_webroot_params_conservation(self, mock_set_by_user):
        # For more details about why this test is important, see:
        # certbot._internal.plugins.webroot_test::
        #   WebrootActionTest::test_webroot_map_partial_without_perform
        from certbot._internal import renewal
        mock_set_by_user.return_value = False

        renewalparams = {
            'webroot_map': {'test.example.com': '/var/www/test'},
            'webroot_path': ['/var/www/test', '/var/www/other'],
        }
        renewal._restore_webroot_config(self.config, renewalparams)  # pylint: disable=protected-access
        assert self.config.webroot_map == {'test.example.com': '/var/www/test'}
        assert self.config.webroot_path == ['/var/www/test', '/var/www/other']

        renewalparams = {
            'webroot_map': {},
            'webroot_path': '/var/www/test',
        }
        renewal._restore_webroot_config(self.config, renewalparams)  # pylint: disable=protected-access
        assert self.config.webroot_map == {}
        assert self.config.webroot_path == ['/var/www/test']

    @mock.patch('certbot._internal.renewal._avoid_reuse_key_conflicts')
    def test_reuse_key_renewal_params(self, unused_mock_avoid_reuse_conflicts):
        self.config.elliptic_curve = 'INVALID_VALUE'
        self.config.reuse_key = True
        self.config.dry_run = True
        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal.conf')
        lineage = storage.RenewableCert(rc_path, config)

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with mock.patch('certbot._internal.renewal.hooks.renew_hook'):
            renewal.renew_cert(self.config, None, le_client, lineage)

        assert self.config.elliptic_curve == 'secp256r1'

    @mock.patch('certbot._internal.renewal._avoid_reuse_key_conflicts')
    def test_reuse_ec_key_renewal_params(self, unused_mock_avoid_reuse_conflicts):
        self.config.elliptic_curve = 'INVALID_CURVE'
        self.config.reuse_key = True
        self.config.dry_run = True
        self.config.key_type = 'ecdsa'
        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir,
            'sample-renewal-ec.conf',
            ec=True,
        )
        lineage = storage.RenewableCert(rc_path, config)

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with mock.patch('certbot._internal.renewal.hooks.renew_hook'):
            renewal.renew_cert(self.config, None, le_client, lineage)

        assert self.config.elliptic_curve == 'secp256r1'

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_new_key(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        # When renewing with both reuse_key and new_key, the key should be regenerated,
        # the key type, key parameters and reuse_key should be kept.
        self.config.reuse_key = True
        self.config.new_key = True
        self.config.dry_run = True
        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal.conf')
        lineage = storage.RenewableCert(rc_path, config)

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with mock.patch('certbot._internal.renewal.hooks.renew_hook'):
            renewal.renew_cert(self.config, None, le_client, lineage)

        assert self.config.elliptic_curve == 'secp256r1'
        assert self.config.key_type == 'ecdsa'
        assert self.config.reuse_key
        # None is passed as the existing key, i.e. the key is not actually being reused.
        le_client.obtain_certificate.assert_called_with(mock.ANY, None)

    @mock.patch('certbot._internal.renewal.hooks.renew_hook')
    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_reuse_key_conflicts(self, mock_set_by_user, unused_mock_renew_hook):
        mock_set_by_user.return_value = False

        # When renewing with reuse_key and a conflicting key parameter (size, curve)
        # an error should be raised ...
        self.config.reuse_key = True
        self.config.key_type = "rsa"
        self.config.rsa_key_size = 4096
        self.config.dry_run = True

        config = configuration.NamespaceConfig(self.config)

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal.conf')
        lineage = storage.RenewableCert(rc_path, config)
        lineage.configuration["renewalparams"]["reuse_key"] = True

        le_client = mock.MagicMock()
        le_client.obtain_certificate.return_value = (None, None, None, None)

        from certbot._internal import renewal

        with pytest.raises(errors.Error, match="Unable to change the --key-type"):
            renewal.renew_cert(self.config, None, le_client, lineage)

        # ... unless --no-reuse-key is set
        mock_set_by_user.side_effect = lambda var: var == "reuse_key"
        self.config.reuse_key = False
        renewal.renew_cert(self.config, None, le_client, lineage)

    @test_util.patch_display_util()
    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_remove_deprecated_config_elements(self, mock_set_by_user, unused_mock_get_utility):
        mock_set_by_user.return_value = False
        config = configuration.NamespaceConfig(self.config)
        config.certname = "sample-renewal-deprecated-option"

        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal-deprecated-option.conf')

        from certbot._internal import renewal
        lineage_config = copy.deepcopy(self.config)
        renewal_candidate = renewal.reconstitute(lineage_config, rc_path)
        # This means that manual_public_ip_logging_ok was not modified in the config based on its
        # value in the renewal conf file
        assert isinstance(lineage_config.manual_public_ip_logging_ok, mock.MagicMock)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_absent_key_type_restored(self, mock_set_by_user):
        mock_set_by_user.return_value = False

        rc_path = test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf', ec=False)

        from certbot._internal import renewal
        lineage_config = copy.deepcopy(self.config)
        renewal.reconstitute(lineage_config, rc_path)
        assert lineage_config.key_type == 'rsa'

    @test_util.patch_display_util()
    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    @mock.patch('certbot._internal.client.create_acme_client')
    @mock.patch('certbot._internal.main.renew_cert')
    @mock.patch("certbot._internal.renewal.datetime")
    def test_renewal_via_ari(self, mock_datetime, mock_renew_cert, mock_acme_from_config, mock_set_by_user, unused_mock_display):
        mock_set_by_user.return_value = False
        from certbot._internal import renewal
        acme_client = mock.MagicMock()
        mock_acme_from_config.return_value = acme_client
        past = datetime.datetime(2025, 3, 19, 0, 0, 0, tzinfo=datetime.timezone.utc)
        now = datetime.datetime(2025, 4, 19, 0, 0, 0, tzinfo=datetime.timezone.utc)
        future = datetime.datetime(2025, 4, 19, 12, 0, 0, tzinfo=datetime.timezone.utc)
        mock_datetime.datetime.now.return_value = now
        acme_client.renewal_time.return_value = past, future

        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf', ec=False)
        config = configuration.NamespaceConfig(self.config)

        with mock.patch('time.sleep') as sleep:
            renewal.handle_renewal_request(config)

        mock_renew_cert.assert_called_once()
        # This value comes from `sample-renewal.conf` and is different than
        # the global default.
        expected_server = "https://acme-staging-v02.api.letsencrypt.org/directory"
        assert expected_server != config.server
        assert mock_acme_from_config.call_args[0][0].server == expected_server

    @test_util.patch_display_util()
    @mock.patch('acme.client.ClientNetwork.get')
    @mock.patch('certbot._internal.storage.RenewableCert.autorenewal_is_enabled')
    def test_no_network_if_no_autorenew(self, mock_autorenewal_enabled,
            mock_client_network_get, unused_mock_display):
        from certbot._internal import renewal
        mock_autorenewal_enabled.return_value = False

        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf', ec=False)

        with mock.patch('time.sleep') as sleep:
            renewal.handle_renewal_request(self.config)

        assert mock_client_network_get.call_count == 0

    @mock.patch('acme.client.ClientV2')
    def test_dry_run_no_ari_call(self, mock_acme):
        from certbot._internal import renewal
        self.config.dry_run = True
        acme_clients = {}
        acme_clients[self.config.server] = mock_acme
        with mock.patch('time.sleep') as sleep:
            renewal.should_renew(self.config, mock.Mock(), acme_clients)
        assert mock_acme.renewal_time.call_count == 0

    def test_default_renewal_time(self):
        from certbot._internal import renewal
        cert_pem = make_cert_with_lifetime(datetime.datetime(2025, 3, 12, 00, 00, 00), 8)
        t = renewal._default_renewal_time(cert_pem)
        assert t == datetime.datetime(2025, 3, 16, 00, 00, 00, tzinfo=datetime.timezone.utc)

        cert_pem = make_cert_with_lifetime(datetime.datetime(2025, 3, 12, 00, 00, 00), 18)
        t = renewal._default_renewal_time(cert_pem)
        assert t == datetime.datetime(2025, 3, 24, 00, 00, 00, tzinfo=datetime.timezone.utc)

    @mock.patch("certbot._internal.renewal.datetime")
    def test_renew_before_expiry(self, mock_datetime):
        """When neither OCSP nor the ACME client indicate it's time to renew,
           obey the renew_before_expiry config.
        """
        from certbot._internal import renewal

        # This certificate has a lifetime of 7 days, and the tests below
        # that use a "None" interval (i.e. choose a default) rely on that fact.
        #
        # Not Before: Dec 11 22:34:45 2014 GMT
        # Not After : Dec 18 22:34:45 2014 GMT
        not_before = datetime.datetime(2014, 12, 11, 22, 34, 45)
        short_cert = make_cert_with_lifetime(not_before, 7)

        ari_server = "http://ari"
        mock_acme = mock.MagicMock()
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=100000)
        mock_acme.renewal_time.return_value = (future, future)
        acme_clients = {}
        acme_clients[ari_server] = mock_acme

        mock_renewable_cert = mock.MagicMock()
        mock_renewable_cert.server = ari_server
        mock_renewable_cert.autorenewal_is_enabled.return_value = True
        mock_renewable_cert.version.return_value = "/tmp/abc"
        mock_renewable_cert.ocsp_revoked.return_value = False

        mock_datetime.timedelta = datetime.timedelta

        with tempfile.NamedTemporaryFile() as tmp_cert:
            tmp_cert.close()  # close now because of compatibility issues on Windows
            with open(tmp_cert.name, 'wb') as c:
                c.write(short_cert)

            mock_renewable_cert.version.return_value = tmp_cert.name

            # First, test cases where ARI returns a renewal_time far in the future
            for (current_time, interval, result) in [
                    # 2014-12-13 12:00 (about 5 days prior to expiry)
                    # Times that should result in autorenewal/autodeployment
                    (1418472000, "2 months", True), (1418472000, "1 week", True),
                    # With the "default" logic, this 7-day certificate should autorenew
                    # at 3.5 days prior to expiry. We haven't reached that yet,
                    # so don't renew.
                    (1418472000, None, False),
                    # Times that should not renew
                    (1418472000, "4 days", False), (1418472000, "2 days", False),
                    # 2014-12-16 20:00 (after the default renewal time but before expiry)
                    # Times that should not renew
                    (1418760000, None, False),
                    (1418760000, "1 day", False),
                    # 2009-05-01 12:00:00+00:00 (about 5 years prior to expiry)
                    # Times that should result in autorenewal/autodeployment
                    (1241179200, "7 years", True),
                    (1241179200, "11 years 2 months", True),
                    # Times that should not renew
                    (1241179200, "8 hours", False), (1241179200, "2 days", False),
                    (1241179200, "40 days", False), (1241179200, "9 months", False),
                    # 2015-01-01 (after expiry has already happened, so all
                    #            intervals should cause autorenewal/autodeployment)
                    (1420070400, "0 seconds", True),
                    (1420070400, "10 seconds", True),
                    (1420070400, "10 minutes", True),
                    (1420070400, "10 weeks", True), (1420070400, "10 months", True),
                    (1420070400, "10 years", True), (1420070400, "99 months", True),
            ]:
                sometime = datetime.datetime.fromtimestamp(current_time, datetime.timezone.utc)
                mock_datetime.datetime.now.return_value = sometime
                mock_renewable_cert.configuration = {"renew_before_expiry": interval}
                assert renewal.should_autorenew(self.config, mock_renewable_cert, acme_clients) == result, f"at {current_time}, with config '{interval}', ari response in future, expected {result}"

            # Now, test cases where ARI either fails (returns `(None, _)`) or
            # the cert has no `server` value and ARI is skipped
            mock_acme.renewal_time.return_value = (None, future)
            for (current_time, interval, result) in [
                    # 2014-12-13 12:00 (about 5 days prior to expiry)
                    # Times that should result in autorenewal/autodeployment
                    (1418472000, "2 months", True), (1418472000, "1 week", True),
                    # With the "default" logic, this 7-day certificate should autorenew
                    # at 3.5 days prior to expiry. We haven't reached that yet,
                    # so don't renew.
                    (1418472000, None, False),
                    # Times that should not renew
                    (1418472000, "4 days", False), (1418472000, "2 days", False),
                    # 2014-12-16 20:00 (after the default renewal time but before expiry)
                    # Times that should result in autorenewal/autodeployment
                    (1418760000, None, True), # Note that this result is different from the above
                    # Times that should not renew
                    (1418760000, "1 day", False),
                    # 2009-05-01 12:00:00+00:00 (about 5 years prior to expiry)
                    # Times that should result in autorenewal/autodeployment
                    (1241179200, "7 years", True),
                    (1241179200, "11 years 2 months", True),
                    # Times that should not renew
                    (1241179200, "8 hours", False), (1241179200, "2 days", False),
                    (1241179200, "40 days", False), (1241179200, "9 months", False),
                    # 2015-01-01 (after expiry has already happened, so all
                    #            intervals should cause autorenewal/autodeployment)
                    (1420070400, "0 seconds", True),
                    (1420070400, "10 seconds", True),
                    (1420070400, "10 minutes", True),
                    (1420070400, "10 weeks", True), (1420070400, "10 months", True),
                    (1420070400, "10 years", True), (1420070400, "99 months", True),
            ]:
                sometime = datetime.datetime.fromtimestamp(current_time, datetime.timezone.utc)
                mock_datetime.datetime.now.return_value = sometime
                mock_renewable_cert.configuration = {"renew_before_expiry": interval}
                mock_renewable_cert.server = ari_server
                assert renewal.should_autorenew(self.config, mock_renewable_cert, acme_clients) == result, f"at {current_time}, with config '{interval}', no ari response, expected {result}"
                mock_renewable_cert.server = None
                assert renewal.should_autorenew(self.config, mock_renewable_cert, acme_clients) == result, f"at {current_time}, with config '{interval}', skipped ari, expected {result}"

    @mock.patch("certbot._internal.storage.RenewableCert.ocsp_revoked")
    def test_should_autorenew(self, mock_ocsp):
        from certbot._internal import renewal

        mock_acme = mock.MagicMock()
        ari_server = "http://ari"
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=1000)
        mock_acme.renewal_time.return_value = (future, future)
        acme_clients = {}
        acme_clients[ari_server] = mock_acme
        mock_rc = mock.MagicMock()

        with mock.patch('certbot._internal.renewal.open', mock.mock_open(read_data=b'')):
            # Autorenewal turned off
            mock_rc.autorenewal_is_enabled.return_value = False
            mock_rc.server = ari_server
            assert not renewal.should_autorenew(self.config, mock_rc, acme_clients)
            mock_rc.server = None
            assert not renewal.should_autorenew(self.config, mock_rc, acme_clients)

            # Autorenewal turned on, mandatory renewal on the basis of OCSP
            # revocation
            mock_rc.autorenewal_is_enabled.return_value = True
            mock_ocsp.return_value = True
            assert renewal.should_autorenew(self.config, mock_rc, acme_clients)
            mock_rc.server = None
            with mock.patch('certbot._internal.renewal.logger.warning') as mock_warning:
                assert renewal.should_autorenew(self.config, mock_rc, acme_clients)
            # Ensure we warned about skipping ARI checks when server is None
            assert any(call.args[0].startswith('Skipping ARI') for call in
                       mock_warning.call_args_list)

    @mock.patch('certbot._internal.client.create_acme_client')
    @mock.patch('certbot._internal.storage.RenewableCert.ocsp_revoked')
    @mock.patch('acme.client.ClientV2.renewal_time')
    def test_resilient_ari_directory_fetches(self, mock_renewal_time, mock_ocsp, mock_create_acme):
        from certbot._internal import renewal
        from acme import messages

        ari_server = 'http://ari'
        acme_clients = {}
        mock_rc = mock.MagicMock()
        mock_rc.server = ari_server
        mock_rc.autorenewal_is_enabled.return_value = True
        mock_create_acme.side_effect = messages.Error()
        mock_ocsp.return_value = True

        with mock.patch('certbot._internal.renewal.open', mock.mock_open(read_data=b'')):
            with mock.patch('certbot._internal.renewal.logger') as mock_logger:
                assert renewal.should_autorenew(self.config, mock_rc, acme_clients)
        assert mock_renewal_time.call_count == 0
        # Ensure we logged about skipping the ARI check and the underlying exception
        assert any('ARI' in call.args[0] for call in mock_logger.warning.call_args_list)
        assert any(call.kwargs.get('exc_info') for call in mock_logger.debug.call_args_list)


    @mock.patch('certbot._internal.storage.RenewableCert.ocsp_revoked')
    def test_resilient_ari_check(self, mock_ocsp):
        from certbot._internal import renewal

        mock_acme = mock.MagicMock()
        ari_error = acme_errors.ARIError('some error', datetime.datetime.now())
        ari_server = 'http://ari'
        mock_acme.renewal_time.side_effect = ari_error
        acme_clients = {}
        acme_clients[ari_server] = mock_acme
        mock_rc = mock.MagicMock()
        mock_rc.server = ari_server
        mock_rc.autorenewal_is_enabled.return_value = True
        mock_ocsp.return_value = True

        with mock.patch('certbot._internal.renewal.open', mock.mock_open(read_data=b'')):
            with mock.patch('certbot._internal.renewal.logger') as mock_logger:
                assert renewal.should_autorenew(self.config, mock_rc, acme_clients)
        # Ensure we logged about skipping the ARI check and the underlying exception
        assert any('ARI' in call.args[0] for call in mock_logger.warning.call_args_list)
        assert any(call.kwargs.get('exc_info') for call in mock_logger.debug.call_args_list)


class RestoreRequiredConfigElementsTest(test_util.ConfigTestCase):
    """Tests for certbot._internal.renewal.restore_required_config_elements."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.renewal import restore_required_config_elements
        return restore_required_config_elements(*args, **kwargs)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_allow_subset_of_names_success(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        self._call(self.config, {'allow_subset_of_names': 'True'})
        assert self.config.allow_subset_of_names is True

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_allow_subset_of_names_failure(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'allow_subset_of_names': 'maybe'}
        with pytest.raises(errors.Error):
            self._call(self.config, renewalparams)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_pref_challs_list(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'pref_challs': 'http-01, dns'.split(',')}
        self._call(self.config, renewalparams)
        expected = [challenges.HTTP01.typ, challenges.DNS01.typ]
        assert self.config.pref_challs == expected

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_pref_challs_str(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'pref_challs': 'dns'}
        self._call(self.config, renewalparams)
        expected = [challenges.DNS01.typ]
        assert self.config.pref_challs == expected

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_pref_challs_failure(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'pref_challs': 'finding-a-shrubbery'}
        with pytest.raises(errors.Error):
            self._call(self.config, renewalparams)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_must_staple_success(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        self._call(self.config, {'must_staple': 'True'})
        assert self.config.must_staple is True

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_must_staple_failure(self, mock_set_by_user):
        mock_set_by_user.return_value = False
        renewalparams = {'must_staple': 'maybe'}
        with pytest.raises(errors.Error):
            self._call(self.config, renewalparams)

    @mock.patch.object(configuration.NamespaceConfig, 'set_by_user')
    def test_ancient_server_renewal_conf(self, mock_set_by_user):
        from certbot._internal import constants
        self.config.server = None
        mock_set_by_user.return_value = False
        self._call(self.config, {'server': constants.V1_URI})
        assert self.config.server == constants.CLI_DEFAULTS['server']

    def test_related_values(self):
        # certbot.configuration.NamespaceConfig.set_by_user considers some values as related to each
        # other and considers both set by the user if either is. This test ensures all renewal
        # parameters are restored regardless of their restoration order or relation between values.
        # See https://github.com/certbot/certbot/issues/9805 for more info.
        renewalparams = {
            'server': 'https://example.org',
            'account': 'somehash',
        }
        self._call(self.config, renewalparams)
        self.assertEqual(self.config.account, renewalparams['account'])


class DescribeResultsTest(unittest.TestCase):
    """Tests for certbot._internal.renewal._renew_describe_results."""
    def setUp(self):
        self.patchers = {
            'log_error': mock.patch('certbot._internal.renewal.logger.error'),
            'notify': mock.patch('certbot._internal.renewal.display_util.notify')}
        self.mock_notify = self.patchers['notify'].start()
        self.mock_error = self.patchers['log_error'].start()

    def tearDown(self):
        for patch in self.patchers.values():
            patch.stop()

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.renewal import _renew_describe_results
        _renew_describe_results(*args, **kwargs)

    def _assert_success_output(self, lines):
        self.mock_notify.assert_has_calls([mock.call(l) for l in lines])

    def test_no_renewal_attempts(self):
        self._call(mock.MagicMock(dry_run=True), [], [], [], [])
        self._assert_success_output(['No simulated renewals were attempted.'])

    def test_successful_renewal(self):
        self._call(mock.MagicMock(dry_run=False), ['good.pem'], None, None, None)
        self._assert_success_output([
            '\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
            'Congratulations, all renewals succeeded: ',
            '  good.pem (success)',
            '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
        ])

    def test_failed_renewal(self):
        self._call(mock.MagicMock(dry_run=False), [], ['bad.pem'], [], [])
        self._assert_success_output([
            '\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
            '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
        ])
        self.mock_error.assert_has_calls([
            mock.call('All %ss failed. The following certificates could not be renewed:', 'renewal'),
            mock.call('  bad.pem (failure)'),
        ])

    def test_all_renewal(self):
        self._call(mock.MagicMock(dry_run=True),
                   ['good.pem', 'good2.pem'], ['bad.pem', 'bad2.pem'],
                   ['foo.pem expires on 123'], ['errored.conf'])
        self._assert_success_output([
            '\n- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
            'The following certificates are not due for renewal yet:',
            '  foo.pem expires on 123 (skipped)',
            'The following simulated renewals succeeded:',
            '  good.pem (success)\n  good2.pem (success)\n',
            '\nAdditionally, the following renewal configurations were invalid: ',
            '  errored.conf (parsefail)',
            '- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -',
        ])
        self.mock_error.assert_has_calls([
            mock.call('The following %ss failed:', 'simulated renewal'),
            mock.call('  bad.pem (failure)\n  bad2.pem (failure)'),
        ])


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
