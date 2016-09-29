# pylint: disable=too-many-public-methods
"""Test for certbot_nginx.configurator."""
import os
import shutil
import unittest

import mock
import OpenSSL

from acme import challenges
from acme import messages

from certbot import achallenges
from certbot import errors

from certbot_nginx import obj
from certbot_nginx import parser
from certbot_nginx.tests import util


class NginxConfiguratorTest(util.NginxTest):
    """Test a semi complex vhost configuration."""

    def setUp(self):
        super(NginxConfiguratorTest, self).setUp()

        self.config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    @mock.patch("certbot_nginx.configurator.util.exe_exists")
    def test_prepare_no_install(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.NoInstallationError, self.config.prepare)

    def test_prepare(self):
        self.assertEqual((1, 6, 2), self.config.version)
        self.assertEqual(6, len(self.config.parser.parsed))
        # ensure we successfully parsed a file for ssl_options
        self.assertTrue(self.config.parser.loc["ssl_options"])

    @mock.patch("certbot_nginx.configurator.util.exe_exists")
    @mock.patch("certbot_nginx.configurator.subprocess.Popen")
    def test_prepare_initializes_version(self, mock_popen, mock_exe_exists):
        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/1.6.2",
                           "built by clang 6.0 (clang-600.0.56)"
                           " (based on LLVM 3.5svn)",
                           "TLS SNI support enabled",
                           "configure arguments: --prefix=/usr/local/Cellar/"
                           "nginx/1.6.2 --with-http_ssl_module"]))

        mock_exe_exists.return_value = True

        self.config.version = None
        self.config.config_test = mock.Mock()
        self.config.prepare()
        self.assertEqual((1, 6, 2), self.config.version)

    @mock.patch("certbot_nginx.configurator.socket.gethostbyaddr")
    def test_get_all_names(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ('155.225.50.69.nephoscale.net', [], [])
        names = self.config.get_all_names()
        self.assertEqual(names, set(
            ["155.225.50.69.nephoscale.net", "www.example.org", "another.alias",
             "migration.com", "summer.com", "geese.com"]))

    def test_supported_enhancements(self):
        self.assertEqual(['redirect', 'staple-ocsp'],
                         self.config.supported_enhancements())

    def test_enhance(self):
        self.assertRaises(
            errors.PluginError, self.config.enhance, 'myhost', 'unknown_enhancement')

    def test_get_chall_pref(self):
        self.assertEqual([challenges.TLSSNI01],
                         self.config.get_chall_pref('myhost'))

    def test_save(self):
        filep = self.config.parser.abs_path('sites-enabled/example.com')
        mock_vhost = obj.VirtualHost(filep,
                                     None, None, None,
                                     set(['.example.com', 'example.*']),
                                     None, [0])
        self.config.parser.add_server_directives(
            mock_vhost,
            [['listen', ' ', '5001 ssl']],
            replace=False)
        self.config.save()

        # pylint: disable=protected-access
        parsed = self.config.parser._parse_files(filep, override=True)
        self.assertEqual([[['server'],
                           [['listen', '69.50.225.155:9000'],
                            ['listen', '127.0.0.1'],
                            ['server_name', '.example.com'],
                            ['server_name', 'example.*'],
                            ['listen', '5001 ssl'],
                            ['#', parser.COMMENT]]]],
                         parsed[0])

    def test_choose_vhost(self):
        localhost_conf = set(['localhost', r'~^(www\.)?(example|bar)\.'])
        server_conf = set(['somename', 'another.alias', 'alias'])
        example_conf = set(['.example.com', 'example.*'])
        foo_conf = set(['*.www.foo.com', '*.www.example.com'])

        results = {'localhost': localhost_conf,
                   'alias': server_conf,
                   'example.com': example_conf,
                   'example.com.uk.test': example_conf,
                   'www.example.com': example_conf,
                   'test.www.example.com': foo_conf,
                   'abc.www.foo.com': foo_conf,
                   'www.bar.co.uk': localhost_conf}

        conf_path = {'localhost': "etc_nginx/nginx.conf",
                   'alias': "etc_nginx/nginx.conf",
                   'example.com': "etc_nginx/sites-enabled/example.com",
                   'example.com.uk.test': "etc_nginx/sites-enabled/example.com",
                   'www.example.com': "etc_nginx/sites-enabled/example.com",
                   'test.www.example.com': "etc_nginx/foo.conf",
                   'abc.www.foo.com': "etc_nginx/foo.conf",
                   'www.bar.co.uk': "etc_nginx/nginx.conf"}

        bad_results = ['www.foo.com', 'example', 't.www.bar.co',
                       '69.255.225.155']

        for name in results:
            vhost = self.config.choose_vhost(name)
            path = os.path.relpath(vhost.filep, self.temp_dir)

            self.assertEqual(results[name], vhost.names)
            self.assertEqual(conf_path[name], path)

        for name in bad_results:
            self.assertRaises(errors.MisconfigurationError,
                              self.config.choose_vhost, name)

    def test_more_info(self):
        self.assertTrue('nginx.conf' in self.config.more_info())

    def test_deploy_cert_requires_fullchain_path(self):
        self.config.version = (1, 3, 1)
        self.assertRaises(errors.PluginError, self.config.deploy_cert,
            "www.example.com",
            "example/cert.pem",
            "example/key.pem",
            "example/chain.pem",
            None)

    def test_deploy_cert(self):
        server_conf = self.config.parser.abs_path('server.conf')
        nginx_conf = self.config.parser.abs_path('nginx.conf')
        example_conf = self.config.parser.abs_path('sites-enabled/example.com')
        self.config.version = (1, 3, 1)

        # Get the default SSL vhost
        self.config.deploy_cert(
            "www.example.com",
            "example/cert.pem",
            "example/key.pem",
            "example/chain.pem",
            "example/fullchain.pem")
        self.config.deploy_cert(
            "another.alias",
            "/etc/nginx/cert.pem",
            "/etc/nginx/key.pem",
            "/etc/nginx/chain.pem",
            "/etc/nginx/fullchain.pem")
        self.config.save()

        self.config.parser.load()

        parsed_example_conf = util.filter_comments(self.config.parser.parsed[example_conf])
        parsed_server_conf = util.filter_comments(self.config.parser.parsed[server_conf])
        parsed_nginx_conf = util.filter_comments(self.config.parser.parsed[nginx_conf])

        self.assertEqual([[['server'],
                           [
                            ['listen', '69.50.225.155:9000'],
                            ['listen', '127.0.0.1'],
                            ['server_name', '.example.com'],
                            ['server_name', 'example.*'],

                            ['listen', '5001 ssl'],
                            ['ssl_certificate', 'example/fullchain.pem'],
                            ['ssl_certificate_key', 'example/key.pem']] +
                            util.filter_comments(self.config.parser.loc["ssl_options"])
                            ]],
                         parsed_example_conf)
        self.assertEqual([['server_name', 'somename  alias  another.alias']],
                         parsed_server_conf)
        self.assertTrue(util.contains_at_depth(
            parsed_nginx_conf,
            [['server'],
             [
              ['listen', '8000'],
              ['listen', 'somename:8080'],
              ['include', 'server.conf'],
              [['location', '/'],
               [['root', 'html'],
                ['index', 'index.html index.htm']]],
              ['listen', '5001 ssl'],
              ['ssl_certificate', '/etc/nginx/fullchain.pem'],
              ['ssl_certificate_key', '/etc/nginx/key.pem']] +
             util.filter_comments(self.config.parser.loc["ssl_options"])
            ],
            2))

    def test_deploy_cert_add_explicit_listen(self):
        migration_conf = self.config.parser.abs_path('sites-enabled/migration.com')
        self.config.deploy_cert(
            "summer.com",
            "summer/cert.pem",
            "summer/key.pem",
            "summer/chain.pem",
            "summer/fullchain.pem")
        self.config.save()
        self.config.parser.load()
        parsed_migration_conf = util.filter_comments(self.config.parser.parsed[migration_conf])
        self.assertEqual([['server'],
                          [
                           ['server_name', 'migration.com'],
                           ['server_name', 'summer.com'],

                           ['listen', '80'],
                           ['listen', '5001 ssl'],
                           ['ssl_certificate', 'summer/fullchain.pem'],
                           ['ssl_certificate_key', 'summer/key.pem']] +
                           util.filter_comments(self.config.parser.loc["ssl_options"])
                           ],
                         parsed_migration_conf[0])

    def test_get_all_certs_keys(self):
        nginx_conf = self.config.parser.abs_path('nginx.conf')
        example_conf = self.config.parser.abs_path('sites-enabled/example.com')
        migration_conf = self.config.parser.abs_path('sites-enabled/migration.com')

        # Get the default SSL vhost
        self.config.deploy_cert(
            "www.example.com",
            "example/cert.pem",
            "example/key.pem",
            "example/chain.pem",
            "example/fullchain.pem")
        self.config.deploy_cert(
            "another.alias",
            "/etc/nginx/cert.pem",
            "/etc/nginx/key.pem",
            "/etc/nginx/chain.pem",
            "/etc/nginx/fullchain.pem")
        self.config.deploy_cert(
            "migration.com",
            "migration/cert.pem",
            "migration/key.pem",
            "migration/chain.pem",
            "migration/fullchain.pem")
        self.config.save()

        self.config.parser.load()
        self.assertEqual(set([
            ('example/fullchain.pem', 'example/key.pem', example_conf),
            ('/etc/nginx/fullchain.pem', '/etc/nginx/key.pem', nginx_conf),
            ('migration/fullchain.pem', 'migration/key.pem', migration_conf),
        ]), self.config.get_all_certs_keys())

    @mock.patch("certbot_nginx.configurator.tls_sni_01.NginxTlsSni01.perform")
    @mock.patch("certbot_nginx.configurator.NginxConfigurator.restart")
    @mock.patch("certbot_nginx.configurator.NginxConfigurator.revert_challenge_config")
    def test_perform_and_cleanup(self, mock_revert, mock_restart, mock_perform):
        # Only tests functionality specific to configurator.perform
        # Note: As more challenges are offered this will have to be expanded
        achall1 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=messages.ChallengeBody(
                chall=challenges.TLSSNI01(token="kNdwjwOeX0I_A8DXt9Msmg"),
                uri="https://ca.org/chall0_uri",
                status=messages.Status("pending"),
            ), domain="localhost", account_key=self.rsa512jwk)
        achall2 = achallenges.KeyAuthorizationAnnotatedChallenge(
            challb=messages.ChallengeBody(
                chall=challenges.TLSSNI01(token="m8TdO1qik4JVFtgPPurJmg"),
                uri="https://ca.org/chall1_uri",
                status=messages.Status("pending"),
            ), domain="example.com", account_key=self.rsa512jwk)

        expected = [
            achall1.response(self.rsa512jwk),
            achall2.response(self.rsa512jwk),
        ]

        mock_perform.return_value = expected
        responses = self.config.perform([achall1, achall2])

        self.assertEqual(mock_perform.call_count, 1)
        self.assertEqual(responses, expected)

        self.config.cleanup([achall1, achall2])
        self.assertEqual(0, self.config._chall_out) # pylint: disable=protected-access
        self.assertEqual(mock_revert.call_count, 1)
        self.assertEqual(mock_restart.call_count, 2)

    @mock.patch("certbot_nginx.configurator.subprocess.Popen")
    def test_get_version(self, mock_popen):
        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/1.4.2",
                           "built by clang 6.0 (clang-600.0.56)"
                           " (based on LLVM 3.5svn)",
                           "TLS SNI support enabled",
                           "configure arguments: --prefix=/usr/local/Cellar/"
                           "nginx/1.6.2 --with-http_ssl_module"]))
        self.assertEqual(self.config.get_version(), (1, 4, 2))

        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/0.9",
                           "built by clang 6.0 (clang-600.0.56)"
                           " (based on LLVM 3.5svn)",
                           "TLS SNI support enabled",
                           "configure arguments: --with-http_ssl_module"]))
        self.assertEqual(self.config.get_version(), (0, 9))

        mock_popen().communicate.return_value = (
            "", "\n".join(["blah 0.0.1",
                           "built by clang 6.0 (clang-600.0.56)"
                           " (based on LLVM 3.5svn)",
                           "TLS SNI support enabled",
                           "configure arguments: --with-http_ssl_module"]))
        self.assertRaises(errors.PluginError, self.config.get_version)

        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/1.4.2",
                           "TLS SNI support enabled"]))
        self.assertRaises(errors.PluginError, self.config.get_version)

        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/1.4.2",
                           "built by clang 6.0 (clang-600.0.56)"
                           " (based on LLVM 3.5svn)",
                           "configure arguments: --with-http_ssl_module"]))
        self.assertRaises(errors.PluginError, self.config.get_version)

        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/0.8.1",
                           "built by clang 6.0 (clang-600.0.56)"
                           " (based on LLVM 3.5svn)",
                           "TLS SNI support enabled",
                           "configure arguments: --with-http_ssl_module"]))
        self.assertRaises(errors.NotSupportedError, self.config.get_version)

        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(errors.PluginError, self.config.get_version)

    @mock.patch("certbot_nginx.configurator.subprocess.Popen")
    def test_nginx_restart(self, mock_popen):
        mocked = mock_popen()
        mocked.communicate.return_value = ('', '')
        mocked.returncode = 0
        self.config.restart()

    @mock.patch("certbot_nginx.configurator.subprocess.Popen")
    def test_nginx_restart_fail(self, mock_popen):
        mocked = mock_popen()
        mocked.communicate.return_value = ('', '')
        mocked.returncode = 1
        self.assertRaises(errors.MisconfigurationError, self.config.restart)

    @mock.patch("certbot_nginx.configurator.subprocess.Popen")
    def test_no_nginx_start(self, mock_popen):
        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(errors.MisconfigurationError, self.config.restart)

    @mock.patch("certbot.util.run_script")
    def test_config_test(self, _):
        self.config.config_test()

    @mock.patch("certbot.util.run_script")
    def test_config_test_bad_process(self, mock_run_script):
        mock_run_script.side_effect = errors.SubprocessError
        self.assertRaises(errors.MisconfigurationError, self.config.config_test)

    @mock.patch("certbot.reverter.Reverter.recovery_routine")
    def test_recovery_routine_throws_error_from_reverter(self, mock_recovery_routine):
        mock_recovery_routine.side_effect = errors.ReverterError("foo")
        self.assertRaises(errors.PluginError, self.config.recovery_routine)

    @mock.patch("certbot.reverter.Reverter.view_config_changes")
    def test_view_config_changes_throws_error_from_reverter(self, mock_view_config_changes):
        mock_view_config_changes.side_effect = errors.ReverterError("foo")
        self.assertRaises(errors.PluginError, self.config.view_config_changes)

    @mock.patch("certbot.reverter.Reverter.rollback_checkpoints")
    def test_rollback_checkpoints_throws_error_from_reverter(self, mock_rollback_checkpoints):
        mock_rollback_checkpoints.side_effect = errors.ReverterError("foo")
        self.assertRaises(errors.PluginError, self.config.rollback_checkpoints)

    @mock.patch("certbot.reverter.Reverter.revert_temporary_config")
    def test_revert_challenge_config_throws_error_from_reverter(self, mock_revert_temporary_config):
        mock_revert_temporary_config.side_effect = errors.ReverterError("foo")
        self.assertRaises(errors.PluginError, self.config.revert_challenge_config)

    @mock.patch("certbot.reverter.Reverter.add_to_checkpoint")
    def test_save_throws_error_from_reverter(self, mock_add_to_checkpoint):
        mock_add_to_checkpoint.side_effect = errors.ReverterError("foo")
        self.assertRaises(errors.PluginError, self.config.save)

    def test_get_snakeoil_paths(self):
        # pylint: disable=protected-access
        cert, key = self.config._get_snakeoil_paths()
        self.assertTrue(os.path.exists(cert))
        self.assertTrue(os.path.exists(key))
        with open(cert) as cert_file:
            OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert_file.read())
        with open(key) as key_file:
            OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, key_file.read())

    def test_redirect_enhance(self):
        # Test that we successfully add a redirect when there is
        # a listen directive
        expected = [
            ['if', '($scheme != "https") '],
            [['return', '301 https://$host$request_uri']]
        ]

        example_conf = self.config.parser.abs_path('sites-enabled/example.com')
        self.config.enhance("www.example.com", "redirect")

        generated_conf = self.config.parser.parsed[example_conf]
        self.assertTrue(util.contains_at_depth(generated_conf, expected, 2))

        # Test that we successfully add a redirect when there is
        # no listen directive
        migration_conf = self.config.parser.abs_path('sites-enabled/migration.com')
        self.config.enhance("migration.com", "redirect")

        generated_conf = self.config.parser.parsed[migration_conf]
        self.assertTrue(util.contains_at_depth(generated_conf, expected, 2))

    def test_redirect_dont_enhance(self):
        # Test that we don't accidentally add redirect to ssl-only block
        with mock.patch("certbot_nginx.configurator.logger") as mock_logger:
            self.config.enhance("geese.com", "redirect")
        self.assertEqual(mock_logger.info.call_args[0][0],
                'No matching insecure server blocks listening on port %s found.')

    def test_staple_ocsp_bad_version(self):
        self.config.version = (1, 3, 1)
        self.assertRaises(errors.PluginError, self.config.enhance,
                          "www.example.com", "staple-ocsp", "chain_path")

    def test_staple_ocsp_no_chain_path(self):
        self.assertRaises(errors.PluginError, self.config.enhance,
                          "www.example.com", "staple-ocsp", None)

    def test_staple_ocsp_internal_error(self):
        self.config.enhance("www.example.com", "staple-ocsp", "chain_path")
        # error is raised because the server block has conflicting directives
        self.assertRaises(errors.PluginError, self.config.enhance,
                          "www.example.com", "staple-ocsp", "different_path")

    def test_staple_ocsp(self):
        chain_path = "example/chain.pem"
        self.config.enhance("www.example.com", "staple-ocsp", chain_path)

        example_conf = self.config.parser.abs_path('sites-enabled/example.com')
        generated_conf = self.config.parser.parsed[example_conf]

        self.assertTrue(util.contains_at_depth(
            generated_conf,
            ['ssl_trusted_certificate', 'example/chain.pem'], 2))
        self.assertTrue(util.contains_at_depth(
            generated_conf, ['ssl_stapling', 'on'], 2))
        self.assertTrue(util.contains_at_depth(
            generated_conf, ['ssl_stapling_verify', 'on'], 2))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
