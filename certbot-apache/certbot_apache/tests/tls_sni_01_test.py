"""Test for certbot_apache.tls_sni_01."""
import shutil
import unittest

import mock

from certbot import errors
from certbot.plugins import common_test

from certbot_apache import obj
from certbot_apache.tests import util

from six.moves import xrange  # pylint: disable=redefined-builtin, import-error


class TlsSniPerformTest(util.ApacheTest):
    """Test the ApacheTlsSni01 challenge."""

    auth_key = common_test.AUTH_KEY
    achalls = common_test.ACHALLS

    def setUp(self):  # pylint: disable=arguments-differ
        super(TlsSniPerformTest, self).setUp()

        config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir,
            self.work_dir)
        config.config.tls_sni_01_port = 443

        from certbot_apache import tls_sni_01
        self.sni = tls_sni_01.ApacheTlsSni01(config)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_perform0(self):
        resp = self.sni.perform()
        self.assertEqual(len(resp), 0)

    @mock.patch("certbot.util.exe_exists")
    @mock.patch("certbot.util.run_script")
    def test_perform1(self, _, mock_exists):
        self.sni.configurator.parser.modules.add("socache_shmcb_module")
        self.sni.configurator.parser.modules.add("ssl_module")

        mock_exists.return_value = True
        self.sni.configurator.parser.update_runtime_variables = mock.Mock()

        achall = self.achalls[0]
        self.sni.add_chall(achall)
        response = self.achalls[0].response(self.auth_key)
        mock_setup_cert = mock.MagicMock(return_value=response)
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        responses = self.sni.perform()
        mock_setup_cert.assert_called_once_with(achall)

        # Check to make sure challenge config path is included in apache config
        self.assertEqual(
            len(self.sni.configurator.parser.find_dir(
                "Include", self.sni.challenge_conf)), 1)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0], response)

    def test_perform2(self):
        # Avoid load module
        self.sni.configurator.parser.modules.add("ssl_module")
        self.sni.configurator.parser.modules.add("socache_shmcb_module")
        acme_responses = []
        for achall in self.achalls:
            self.sni.add_chall(achall)
            acme_responses.append(achall.response(self.auth_key))

        mock_setup_cert = mock.MagicMock(side_effect=acme_responses)
        # pylint: disable=protected-access
        self.sni._setup_challenge_cert = mock_setup_cert

        with mock.patch(
            "certbot_apache.override_debian.DebianConfigurator.enable_mod"):
            sni_responses = self.sni.perform()

        self.assertEqual(mock_setup_cert.call_count, 2)

        # Make sure calls made to mocked function were correct
        self.assertEqual(
            mock_setup_cert.call_args_list[0], mock.call(self.achalls[0]))
        self.assertEqual(
            mock_setup_cert.call_args_list[1], mock.call(self.achalls[1]))

        self.assertEqual(
            len(self.sni.configurator.parser.find_dir(
                "Include", self.sni.challenge_conf)),
            1)
        self.assertEqual(len(sni_responses), 2)
        for i in xrange(2):
            self.assertEqual(sni_responses[i], acme_responses[i])

    def test_mod_config(self):
        z_domains = []
        for achall in self.achalls:
            self.sni.add_chall(achall)
            z_domain = achall.response(self.auth_key).z_domain
            z_domains.append(set([z_domain.decode('ascii')]))

        self.sni._mod_config()  # pylint: disable=protected-access
        self.sni.configurator.save()

        self.sni.configurator.parser.find_dir(
            "Include", self.sni.challenge_conf)
        vh_match = self.sni.configurator.aug.match(
            "/files" + self.sni.challenge_conf + "//VirtualHost")

        vhs = []
        for match in vh_match:
            # pylint: disable=protected-access
            vhs.append(self.sni.configurator._create_vhost(match))
        self.assertEqual(len(vhs), 2)
        for vhost in vhs:
            self.assertEqual(vhost.addrs, set([obj.Addr.fromstring("*:443")]))
            names = vhost.get_names()
            self.assertTrue(names in z_domains)

    def test_get_addrs_default(self):
        self.sni.configurator.choose_vhost = mock.Mock(
            return_value=obj.VirtualHost(
                "path", "aug_path",
                set([obj.Addr.fromstring("_default_:443")]),
                False, False)
        )

        # pylint: disable=protected-access
        self.assertEqual(
            set([obj.Addr.fromstring("*:443")]),
            self.sni._get_addrs(self.achalls[0]))

    def test_get_addrs_no_vhost_found(self):
        self.sni.configurator.choose_vhost = mock.Mock(
            side_effect=errors.MissingCommandlineFlag(
                "Failed to run Apache plugin non-interactively"))

        # pylint: disable=protected-access
        self.assertEqual(
            set([obj.Addr.fromstring("*:443")]),
            self.sni._get_addrs(self.achalls[0]))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
