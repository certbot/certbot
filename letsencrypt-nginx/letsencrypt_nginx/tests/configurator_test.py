# pylint: disable=too-many-public-methods
"""Test for letsencrypt_nginx.configurator."""
import os
import shutil
import unittest

import mock
import OpenSSL

from acme import challenges
from acme import messages

from letsencrypt import achallenges
from letsencrypt import errors

from letsencrypt_nginx.tests import util


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

    @mock.patch("letsencrypt_nginx.configurator.le_util.exe_exists")
    def test_prepare_no_install(self, mock_exe_exists):
        mock_exe_exists.return_value = False
        self.assertRaises(
            errors.NoInstallationError, self.config.prepare)

    def test_prepare(self):
        self.assertEquals((1, 6, 2), self.config.version)
        self.assertEquals(5, len(self.config.parser.parsed))

    @mock.patch("letsencrypt_nginx.configurator.socket.gethostbyaddr")
    def test_get_all_names(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ('155.225.50.69.nephoscale.net', [], [])
        names = self.config.get_all_names()
        self.assertEqual(names, set(
            ["*.www.foo.com", "somename", "another.alias",
             "alias", "localhost", ".example.com", r"~^(www\.)?(example|bar)\.",
             "155.225.50.69.nephoscale.net", "*.www.example.com",
             "example.*", "www.example.org", "myhost"]))

    def test_supported_enhancements(self):
        self.assertEqual(['redirect'], self.config.supported_enhancements())

    def test_enhance(self):
        self.assertRaises(
            errors.PluginError, self.config.enhance, 'myhost', 'unknown_enhancement')

    def test_get_chall_pref(self):
        self.assertEqual([challenges.TLSSNI01],
                         self.config.get_chall_pref('myhost'))

    def test_save(self):
        filep = self.config.parser.abs_path('sites-enabled/example.com')
        self.config.parser.add_server_directives(
            filep, set(['.example.com', 'example.*']),
            [['listen', '5001 ssl']])
        self.config.save()

        # pylint: disable=protected-access
        parsed = self.config.parser._parse_files(filep, override=True)
        self.assertEqual([[['server'], [['listen', '5001 ssl'],
                                        ['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*']]]],
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
        bad_results = ['www.foo.com', 'example', 't.www.bar.co',
                       '69.255.225.155']

        for name in results:
            self.assertEqual(results[name],
                             self.config.choose_vhost(name).names)
        for name in bad_results:
            self.assertEqual(set([name]), self.config.choose_vhost(name).names)

    def test_more_info(self):
        self.assertTrue('nginx.conf' in self.config.more_info())

    def test_deploy_cert_stapling(self):
        # Choose a version of Nginx greater than 1.3.7 so stapling code gets
        # invoked.
        self.config.version = (1, 9, 6)
        example_conf = self.config.parser.abs_path('sites-enabled/example.com')
        self.config.deploy_cert(
            "www.example.com",
            "example/cert.pem",
            "example/key.pem",
            "example/chain.pem",
            "example/fullchain.pem")
        self.config.save()
        self.config.parser.load()
        generated_conf = self.config.parser.parsed[example_conf]

        self.assertTrue(util.contains_at_depth(generated_conf,
                                               ['ssl_stapling', 'on'], 2))
        self.assertTrue(util.contains_at_depth(generated_conf,
                                               ['ssl_stapling_verify', 'on'], 2))
        self.assertTrue(util.contains_at_depth(generated_conf,
                                               ['ssl_trusted_certificate', 'example/chain.pem'], 2))

    def test_deploy_cert(self):
        server_conf = self.config.parser.abs_path('server.conf')
        nginx_conf = self.config.parser.abs_path('nginx.conf')
        example_conf = self.config.parser.abs_path('sites-enabled/example.com')
        # Choose a version of Nginx less than 1.3.7 so stapling code doesn't get
        # invoked.
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

        access_log = os.path.join(self.work_dir, "access.log")
        error_log = os.path.join(self.work_dir, "error.log")
        self.assertEqual([[['server'],
                           [['include', self.config.parser.loc["ssl_options"]],
                            ['ssl_certificate_key', 'example/key.pem'],
                            ['ssl_certificate', 'example/fullchain.pem'],
                            ['error_log', error_log],
                            ['access_log', access_log],

                            ['listen', '5001 ssl'],
                            ['listen', '69.50.225.155:9000'],
                            ['listen', '127.0.0.1'],
                            ['server_name', '.example.com'],
                            ['server_name', 'example.*']]]],
                         parsed_example_conf)
        self.assertEqual([['server_name', 'somename  alias  another.alias']],
                         parsed_server_conf)
        self.assertTrue(util.contains_at_depth(parsed_nginx_conf,
                                               [['server'],
                                                [['include', self.config.parser.loc["ssl_options"]],
                                                 ['ssl_certificate_key', '/etc/nginx/key.pem'],
                                                 ['ssl_certificate', '/etc/nginx/fullchain.pem'],
                                                 ['error_log', error_log],
                                                 ['access_log', access_log],
                                                 ['listen', '5001 ssl'],
                                                 ['listen', '8000'],
                                                 ['listen', 'somename:8080'],
                                                 ['include', 'server.conf'],
                                                 [['location', '/'],
                                                  [['root', 'html'],
                                                   ['index', 'index.html index.htm']]]]],
                                               2))

    def test_get_all_certs_keys(self):
        nginx_conf = self.config.parser.abs_path('nginx.conf')
        example_conf = self.config.parser.abs_path('sites-enabled/example.com')

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
        self.assertEqual(set([
            ('example/fullchain.pem', 'example/key.pem', example_conf),
            ('/etc/nginx/fullchain.pem', '/etc/nginx/key.pem', nginx_conf),
        ]), self.config.get_all_certs_keys())

    @mock.patch("letsencrypt_nginx.configurator.tls_sni_01.NginxTlsSni01.perform")
    @mock.patch("letsencrypt_nginx.configurator.NginxConfigurator.restart")
    def test_perform(self, mock_restart, mock_perform):
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
        self.assertEqual(mock_restart.call_count, 1)

    @mock.patch("letsencrypt_nginx.configurator.subprocess.Popen")
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

    @mock.patch("letsencrypt_nginx.configurator.subprocess.Popen")
    def test_nginx_restart(self, mock_popen):
        mocked = mock_popen()
        mocked.communicate.return_value = ('', '')
        mocked.returncode = 0
        self.assertTrue(self.config.restart())

    @mock.patch("letsencrypt_nginx.configurator.subprocess.Popen")
    def test_nginx_restart_fail(self, mock_popen):
        mocked = mock_popen()
        mocked.communicate.return_value = ('', '')
        mocked.returncode = 1
        self.assertFalse(self.config.restart())

    @mock.patch("letsencrypt_nginx.configurator.subprocess.Popen")
    def test_no_nginx_start(self, mock_popen):
        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(SystemExit, self.config.restart)

    @mock.patch("letsencrypt_nginx.configurator.subprocess.Popen")
    def test_config_test(self, mock_popen):
        mocked = mock_popen()
        mocked.communicate.return_value = ('', '')
        mocked.returncode = 0
        self.assertTrue(self.config.config_test())

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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
