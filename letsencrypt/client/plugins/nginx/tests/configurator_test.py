"""Test for letsencrypt.client.plugins.nginx.configurator."""
import shutil
import unittest

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import errors

from letsencrypt.client.plugins.nginx.tests import util


class NginxConfiguratorTest(util.NginxTest):
    """Test a semi complex vhost configuration."""

    def setUp(self):
        super(NginxConfiguratorTest, self).setUp()

        self.config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir,
            self.ssl_options)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_prepare(self):
        self.assertEquals((1, 6, 2), self.config.version)
        self.assertEquals(5, len(self.config.vhosts))

    def test_get_all_names(self):
        names = self.config.get_all_names()
        self.assertEqual(names, set(
            ["*.www.foo.com", "somename", "another.alias",
             "alias", "localhost", ".example.com",
             "155.225.50.69.nephoscale.net", "*.www.example.com",
             "example.*", "www.example.org", "myhost"]))

    def test_supported_enhancements(self):
        self.assertEqual([], self.config.supported_enhancements())

    def test_enhance(self):
        self.assertRaises(errors.LetsEncryptConfiguratorError,
                          self.config.enhance,
                          'myhost',
                          'redirect')

    def test_get_chall_pref(self):
        self.assertEqual([challenges.DVSNI],
                         self.config.get_chall_pref('myhost'))

    def test_save(self):
        filep = self.config.parser.abs_path('sites-enabled/example.com')
        self.config.parser.add_server_directives(
            filep, set(['.example.com', 'example.*']),
            [['listen', '443 ssl']])
        self.config.save()

        # pylint: disable=protected-access
        parsed = self.config.parser._parse_files(filep, override=True)
        self.assertEqual([[['server'], [['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*'],
                                        ['listen', '443 ssl']]]],
                         parsed[0])

    def test_choose_vhost(self):
        localhost_conf = set(['localhost'])
        server_conf = set(['somename', 'another.alias', 'alias'])
        example_conf = set(['.example.com', 'example.*'])
        foo_conf = set(['*.www.foo.com', '*.www.example.com'])

        results = {'localhost': localhost_conf,
                   'alias': server_conf,
                   'example.com': example_conf,
                   'example.com.uk.test': example_conf,
                   'www.example.com': example_conf,
                   'test.www.example.com': foo_conf,
                   'abc.www.foo.com': foo_conf}
        bad_results = ['www.foo.com', 'example', '69.255.225.155']

        for name in results:
            self.assertEqual(results[name],
                             self.config.choose_vhost(name).names)
        for name in bad_results:
            self.assertEqual(None, self.config.choose_vhost(name))

    def test_more_info(self):
        self.assertTrue('nginx.conf' in self.config.more_info())

    def test_deploy_cert(self):
        pass
        # Get the default 443 vhost
#        self.config.assoc["random.demo"] = self.vh_truth[1]
#        self.config.deploy_cert(
#            "random.demo",
#            "example/cert.pem", "example/key.pem", "example/cert_chain.pem")
#        self.config.save()
#
#        loc_cert = self.config.parser.find_dir(
#            parser.case_i("sslcertificatefile"),
#            re.escape("example/cert.pem"), self.vh_truth[1].path)
#        loc_key = self.config.parser.find_dir(
#            parser.case_i("sslcertificateKeyfile"),
#            re.escape("example/key.pem"), self.vh_truth[1].path)
#        loc_chain = self.config.parser.find_dir(
#            parser.case_i("SSLCertificateChainFile"),
#            re.escape("example/cert_chain.pem"), self.vh_truth[1].path)
#
#        # Verify one directive was found in the correct file
#        self.assertEqual(len(loc_cert), 1)
#        self.assertEqual(configurator.get_file_path(loc_cert[0]),
#                         self.vh_truth[1].filep)
#
#        self.assertEqual(len(loc_key), 1)
#        self.assertEqual(configurator.get_file_path(loc_key[0]),
#                         self.vh_truth[1].filep)
#
#        self.assertEqual(len(loc_chain), 1)
#        self.assertEqual(configurator.get_file_path(loc_chain[0]),
#                         self.vh_truth[1].filep)

    def test_make_vhost_ssl(self):
        pass
#        ssl_vhost = self.config.make_vhost_ssl(self.vh_truth[0])
#
#        self.assertEqual(
#            ssl_vhost.filep,
#            os.path.join(self.config_path, "sites-available",
#                         "encryption-example-le-ssl.conf"))
#
#        self.assertEqual(ssl_vhost.path,
#                         "/files" + ssl_vhost.filep + "/IfModule/VirtualHost")
#        self.assertEqual(len(ssl_vhost.addrs), 1)
#        self.assertEqual(set([obj.Addr.fromstring("*:443")]), ssl_vhost.addrs)
#        self.assertEqual(ssl_vhost.names, set(["encryption-example.demo"]))
#        self.assertTrue(ssl_vhost.ssl)
#        self.assertFalse(ssl_vhost.enabled)
#
#        self.assertTrue(self.config.parser.find_dir(
#            "SSLCertificateFile", None, ssl_vhost.path))
#        self.assertTrue(self.config.parser.find_dir(
#            "SSLCertificateKeyFile", None, ssl_vhost.path))
#        self.assertTrue(self.config.parser.find_dir(
#            "Include", self.ssl_options, ssl_vhost.path))
#
#        self.assertEqual(self.config.is_name_vhost(self.vh_truth[0]),
#                         self.config.is_name_vhost(ssl_vhost))
#
#        self.assertEqual(len(self.config.vhosts), 5)

    @mock.patch("letsencrypt.client.plugins.nginx.configurator."
                "dvsni.NginxDvsni.perform")
    @mock.patch("letsencrypt.client.plugins.nginx.configurator."
                "NginxConfigurator.restart")
    def test_perform(self, mock_restart, mock_dvsni_perform):
        # Only tests functionality specific to configurator.perform
        # Note: As more challenges are offered this will have to be expanded
        pass
#        auth_key = le_util.Key(self.rsa256_file, self.rsa256_pem)
#        achall1 = achallenges.DVSNI(
#            chall=challenges.DVSNI(
#                r="jIq_Xy1mXGN37tb4L6Xj_es58fW571ZNyXekdZzhh7Q",
#                nonce="37bc5eb75d3e00a19b4f6355845e5a18"),
#            domain="encryption-example.demo", key=auth_key)
#        achall2 = achallenges.DVSNI(
#            chall=challenges.DVSNI(
#                r="uqnaPzxtrndteOqtrXb0Asl5gOJfWAnnx6QJyvcmlDU",
#                nonce="59ed014cac95f77057b1d7a1b2c596ba"),
#            domain="letsencrypt.demo", key=auth_key)
#
#        dvsni_ret_val = [
#            challenges.DVSNIResponse(s="randomS1"),
#            challenges.DVSNIResponse(s="randomS2"),
#        ]
#
#        mock_dvsni_perform.return_value = dvsni_ret_val
#        responses = self.config.perform([achall1, achall2])
#
#        self.assertEqual(mock_dvsni_perform.call_count, 1)
#        self.assertEqual(responses, dvsni_ret_val)
#
#        self.assertEqual(mock_restart.call_count, 1)

    @mock.patch("letsencrypt.client.plugins.nginx.configurator."
                "subprocess.Popen")
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
            "", "\n".join(["blah 0.0.1",
                           "TLS SNI support enabled"]))
        self.assertRaises(errors.LetsEncryptConfiguratorError,
                          self.config.get_version)

        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/1.4.2",
                           ""]))
        self.assertRaises(errors.LetsEncryptConfiguratorError,
                          self.config.get_version)

        mock_popen().communicate.return_value = (
            "", "\n".join(["nginx version: nginx/0.8.1",
                           ""]))
        self.assertRaises(errors.LetsEncryptConfiguratorError,
                          self.config.get_version)

        mock_popen.side_effect = OSError("Can't find program")
        self.assertRaises(
            errors.LetsEncryptConfiguratorError, self.config.get_version)

    @mock.patch("letsencrypt.client.plugins.nginx.configurator."
                "subprocess.Popen")
    def test_nginx_restart(self, mock_popen):
        m = mock_popen()
        m.communicate.return_value = ('', '')
        m.returncode = 0
        self.assertTrue(self.config.restart())

    @mock.patch("letsencrypt.client.plugins.nginx.configurator."
                "subprocess.Popen")
    def test_config_test(self, mock_popen):
        m = mock_popen()
        m.communicate.return_value = ('', '')
        m.returncode = 0
        self.assertTrue(self.config.config_test())

if __name__ == "__main__":
    unittest.main()
