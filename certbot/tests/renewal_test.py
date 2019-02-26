"""Tests for certbot.renewal"""
from __future__ import print_function

import mock
import unittest
import datetime
import os
import six
import traceback

from acme import challenges

from certbot import configuration
from certbot import errors
from certbot import storage
from certbot import main

import certbot.tests.util as test_util

CSR = test_util.vector_path('csr_512.der')


class RenewalTest(test_util.ConfigTestCase):
    def setUp(self):
        super(RenewalTest, self).setUp()
        self.standard_args = ['--config-dir', self.config.config_dir,
                              '--work-dir', self.config.work_dir,
                              '--logs-dir', self.config.logs_dir, '--text']

        self.mock_sleep = mock.patch('time.sleep').start()

    def _dump_log(self):
        print("Logs:")
        log_path = os.path.join(self.config.logs_dir, "letsencrypt.log")
        if os.path.exists(log_path):
            with open(log_path) as lf:
                print(lf.read())

    def test_reuse_key(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "--reuse-key"]
        self._test_renewal_common(True, [], args=args, should_renew=True, reuse_key=True)

    def _call(self, args, stdout=None, mockisfile=False):
        """Run the cli with output streams, actual client and optionally
        os.path.isfile() mocked out"""

        if mockisfile:
            orig_open = os.path.isfile
            def mock_isfile(fn, *args, **kwargs):  # pylint: disable=unused-argument
                """Mock os.path.isfile()"""
                if (fn.endswith("cert") or
                    fn.endswith("chain") or
                    fn.endswith("privkey")):
                    return True
                else:
                    return orig_open(fn)

            with mock.patch("os.path.isfile") as mock_if:
                mock_if.side_effect = mock_isfile
                with mock.patch('certbot.main.client') as client:
                    ret, stdout, stderr = self._call_no_clientmock(args, stdout)
                    return ret, stdout, stderr, client
        else:
            with mock.patch('certbot.main.client') as client:
                ret, stdout, stderr = self._call_no_clientmock(args, stdout)
                return ret, stdout, stderr, client

    def _call_no_clientmock(self, args, stdout=None):
        "Run the client with output streams mocked out"
        args = self.standard_args + args

        toy_stdout = stdout if stdout else six.StringIO()
        with mock.patch('certbot.main.sys.stdout', new=toy_stdout):
            with mock.patch('certbot.main.sys.stderr') as stderr:
                with mock.patch("certbot.util.atexit"):
                    ret = main.main(args[:])  # NOTE: parser can alter its args!
        return ret, toy_stdout, stderr

    @mock.patch('certbot.cli.set_by_cli')
    def test_ancient_webroot_renewal_conf(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        rc_path = test_util.make_lineage(
            self.config.config_dir, 'sample-renewal-ancient.conf')
        self.config.account = None
        self.config.email = None
        self.config.webroot_path = None
        config = configuration.NamespaceConfig(self.config)
        lineage = storage.RenewableCert(rc_path, config)
        renewalparams = lineage.configuration['renewalparams']
        # pylint: disable=protected-access
        from certbot import renewal
        renewal._restore_webroot_config(config, renewalparams)
        self.assertEqual(config.webroot_path, ['/var/www/'])

    # Refactoring renewal common
    def _test_renewal_common(self, due_for_renewal, extra_args, log_out=None,
                             args=None, should_renew=True, error_expected=False,
                             quiet_mode=False, expiry_date=datetime.datetime.now(),
                             reuse_key=False):
        # pylint: disable=too-many-locals,too-many-arguments,too-many-branches
        cert_path = test_util.vector_path('cert_512.pem')
        chain_path = os.path.normpath(os.path.join(self.config.config_dir,
                                                   'live/foo.bar/fullchain.pem'))
        mock_lineage = mock.MagicMock(cert=cert_path, fullchain=chain_path,
                                      cert_path=cert_path, fullchain_path=chain_path)
        mock_lineage.should_autorenew.return_value = due_for_renewal
        mock_lineage.has_pending_deployment.return_value = False
        mock_lineage.names.return_value = ['isnot.org']
        mock_certr = mock.MagicMock()
        mock_key = mock.MagicMock(pem='pem_key')
        mock_client = mock.MagicMock()
        stdout = six.StringIO()
        mock_client.obtain_certificate.return_value = (mock_certr, 'chain',
                                                       mock_key, 'csr')

        def write_msg(message, *args, **kwargs):  # pylint: disable=unused-argument
            """Write message to stdout."""
            stdout.write(message)

        try:
            with mock.patch('certbot.cert_manager.find_duplicative_certs') as mock_fdc:
                mock_fdc.return_value = (mock_lineage, None)
                with mock.patch('certbot.main._init_le_client') as mock_init:
                    mock_init.return_value = mock_client
                    with test_util.patch_get_utility() as mock_get_utility:
                        if not quiet_mode:
                            mock_get_utility().notification.side_effect = write_msg
                        with mock.patch('certbot.main.renewal.OpenSSL') as mock_ssl:
                            mock_latest = mock.MagicMock()
                            mock_latest.get_issuer.return_value = "Fake fake"
                            mock_ssl.crypto.load_certificate.return_value = mock_latest
                            with mock.patch('certbot.main.renewal.crypto_util') as mock_crypto_util:
                                mock_crypto_util.notAfter.return_value = expiry_date
                                if not args:
                                    args = ['-d', 'isnot.org', '-a', 'standalone', 'certonly']
                                if extra_args:
                                    args += extra_args
                                try:
                                    ret, stdout, _, _ = self._call(args, stdout)
                                    if ret:
                                        print("Returned", ret)
                                        raise AssertionError(ret)
                                    assert not error_expected, "renewal should have errored"
                                except: # pylint: disable=bare-except
                                    if not error_expected:
                                        raise AssertionError(
                                            "Unexpected renewal error:\n" +
                                            traceback.format_exc())

            if should_renew:
                if reuse_key:
                    # The location of the previous live privkey.pem is passed
                    # to obtain_certificate
                    mock_client.obtain_certificate.assert_called_once_with(['isnot.org'],
                        os.path.normpath(os.path.join(
                            self.config.config_dir, "live/sample-renewal/privkey.pem")))
                else:
                    mock_client.obtain_certificate.assert_called_once_with(['isnot.org'], None)
            else:
                self.assertEqual(mock_client.obtain_certificate.call_count, 0)
        except:
            self._dump_log()
            raise
        finally:
            if log_out:
                with open(os.path.join(self.config.logs_dir, "letsencrypt.log")) as lf:
                    self.assertTrue(log_out in lf.read())

        return mock_lineage, mock_get_utility, stdout

    def test_renew_with_bad_certname(self):
        self._test_renewal_common(True, [], should_renew=False,
                                  args=['renew', '--dry-run', '--cert-name', 'sample-renewal'],
                                  error_expected=True)

    def test_renew_with_certname(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        self._test_renewal_common(True, [], should_renew=True,
                                  args=['renew', '--dry-run', '--cert-name', 'sample-renewal'])

    def test_renew_verb(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, should_renew=True)

    @mock.patch('certbot.hooks.post_hook')
    def test_renew_no_hook_validation(self, unused_post_hook):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "--post-hook=no-such-command",
                "--disable-hook-validation"]
        self._test_renewal_common(True, [], args=args, should_renew=True,
                                      error_expected=False)

    @mock.patch('certbot.storage.RenewableCert.save_successor')
    def test_reuse_key_no_dry_run(self, unused_save_successor):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--reuse-key"]
        self._test_renewal_common(True, [], args=args, should_renew=True, reuse_key=True)


    def test_renew_hook_validation(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "--post-hook=no-such-command"]
        self._test_renewal_common(True, [], args=args, should_renew=False,
                                  error_expected=True)

    def test_renew_bad_cli_args_with_split(self):
        self._test_renewal_common(True, None, args='renew -d example.com'.split(),
                                  should_renew=False, error_expected=True)

    def test_renew_bad_cli_args_with_format(self):
        self._test_renewal_common(True, None, args='renew --csr {0}'.format(CSR).split(),
                                  should_renew=False, error_expected=True)

    def test_renew_verb_empty_config(self):
        rd = os.path.join(self.config.config_dir, 'renewal')
        if not os.path.exists(rd):
            os.makedirs(rd)
        with open(os.path.join(rd, 'empty.conf'), 'w'):
            pass  # leave the file empty
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(False, [], args=args, should_renew=False, error_expected=True)

    @mock.patch('sys.stdin')
    def test_noninteractive_renewal_delay(self, stdin):
        stdin.isatty.return_value = False
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, should_renew=True)
        self.assertEqual(self.mock_sleep.call_count, 1)
        # in main.py:
        #     sleep_time = random.randint(1, 60*8)
        sleep_call_arg = self.mock_sleep.call_args[0][0]
        self.assertTrue(1 <= sleep_call_arg <= 60*8)

    @mock.patch('sys.stdin')
    def test_interactive_no_renewal_delay(self, stdin):
        stdin.isatty.return_value = True
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "-tvv"]
        self._test_renewal_common(True, [], args=args, should_renew=True)
        self.assertEqual(self.mock_sleep.call_count, 0)

    @test_util.broken_on_windows
    def test_renew(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run"]
        _, _, stdout = self._test_renewal_common(True, [], args=args, should_renew=True)
        out = stdout.getvalue()
        self.assertTrue("renew" in out)

    @test_util.broken_on_windows
    def test_quiet_renew(self):
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        args = ["renew", "--dry-run", "-q"]
        _, _, stdout = self._test_renewal_common(True, [], args=args,
                                                 should_renew=True, quiet_mode=True)
        out = stdout.getvalue()
        self.assertEqual("", out)

    @mock.patch('certbot.renewal.should_renew')
    def test_renew_skips_recent_certs(self, should_renew):
        should_renew.return_value = False
        test_util.make_lineage(self.config.config_dir, 'sample-renewal.conf')
        expiry = datetime.datetime.now() + datetime.timedelta(days=90)
        _, _, stdout = self._test_renewal_common(False, extra_args=None, should_renew=False,
                                                 args=['renew'], expiry_date=expiry)
        self.assertTrue('No renewals were attempted.' in stdout.getvalue())
        self.assertTrue('The following certs are not due for renewal yet:' in stdout.getvalue())

    def test_certonly_renewal_lineage(self):
        lineage, _, _ = self._test_renewal_common(True, [])
        self.assertEqual(lineage.save_successor.call_count, 1)
        lineage.update_all_links_to.assert_called_once_with(
            lineage.latest_common_version())

    @mock.patch('certbot.crypto_util.notAfter')
    def test_certonly_renewal_get_utillity(self, unused_notafter):
        _, get_utility, _ = self._test_renewal_common(True, [])

        cert_msg = get_utility().add_message.call_args_list[0][0][0]
        self.assertTrue('fullchain.pem' in cert_msg)
        self.assertTrue('donate' in get_utility().add_message.call_args[0][0])


class RestoreRequiredConfigElementsTest(test_util.ConfigTestCase):
    """Tests for certbot.renewal.restore_required_config_elements."""
    def setUp(self):
        super(RestoreRequiredConfigElementsTest, self).setUp()

    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.renewal import restore_required_config_elements
        return restore_required_config_elements(*args, **kwargs)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_allow_subset_of_names_success(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        self._call(self.config, {'allow_subset_of_names': 'True'})
        self.assertTrue(self.config.allow_subset_of_names is True)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_allow_subset_of_names_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'allow_subset_of_names': 'maybe'}
        self.assertRaises(
            errors.Error, self._call, self.config, renewalparams)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_pref_challs_list(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'pref_challs': 'tls-sni, http-01, dns'.split(',')}
        self._call(self.config, renewalparams)
        expected = [challenges.TLSSNI01.typ,
                    challenges.HTTP01.typ, challenges.DNS01.typ]
        self.assertEqual(self.config.pref_challs, expected)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_pref_challs_str(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'pref_challs': 'dns'}
        self._call(self.config, renewalparams)
        expected = [challenges.DNS01.typ]
        self.assertEqual(self.config.pref_challs, expected)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_pref_challs_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'pref_challs': 'finding-a-shrubbery'}
        self.assertRaises(errors.Error, self._call, self.config, renewalparams)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_must_staple_success(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        self._call(self.config, {'must_staple': 'True'})
        self.assertTrue(self.config.must_staple is True)

    @mock.patch('certbot.renewal.cli.set_by_cli')
    def test_must_staple_failure(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        renewalparams = {'must_staple': 'maybe'}
        self.assertRaises(
            errors.Error, self._call, self.config, renewalparams)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
