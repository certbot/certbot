"""Test for letsencrypt_nginx.dvsni."""
import pkg_resources
import unittest
import shutil

import mock

from acme import challenges
from acme import messages2

from letsencrypt import achallenges
from letsencrypt import le_util

from letsencrypt_nginx.tests import util


class DvsniPerformTest(util.NginxTest):
    """Test the NginxDVSNI challenge."""

    def setUp(self):
        super(DvsniPerformTest, self).setUp()

        config = util.get_nginx_configurator(
            self.config_path, self.config_dir, self.work_dir,
            self.ssl_options)

        rsa256_file = pkg_resources.resource_filename(
            "acme.jose", "testdata/rsa256_key.pem")
        rsa256_pem = pkg_resources.resource_string(
            "acme.jose", "testdata/rsa256_key.pem")

        auth_key = le_util.Key(rsa256_file, rsa256_pem)

        from letsencrypt_nginx import dvsni
        self.sni = dvsni.NginxDvsni(config)

        self.achalls = [
            achallenges.DVSNI(
                challb=messages2.ChallengeBody(
                    chall=challenges.DVSNI(
                        r="foo",
                        nonce="bar",
                    ),
                    uri="https://letsencrypt-ca.org/chall0_uri",
                    status=messages2.Status("pending"),
                ), domain="www.example.com", key=auth_key),
            achallenges.DVSNI(
                challb=messages2.ChallengeBody(
                    chall=challenges.DVSNI(
                        r="\xba\xa9\xda?<m\xaewmx\xea\xad\xadv\xf4\x02\xc9y\x80"
                          "\xe2_X\t\xe7\xc7\xa4\t\xca\xf7&\x945",
                        nonce="Y\xed\x01L\xac\x95\xf7pW\xb1\xd7"
                              "\xa1\xb2\xc5\x96\xba",
                    ),
                    uri="https://letsencrypt-ca.org/chall1_uri",
                    status=messages2.Status("pending"),
                ), domain="blah", key=auth_key),
        ]

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_add_chall(self):
        self.sni.add_chall(self.achalls[0], 0)
        self.assertEqual(1, len(self.sni.achalls))
        self.assertEqual([0], self.sni.indices)

    @mock.patch("letsencrypt_nginx.configurator.NginxConfigurator.save")
    def test_perform0(self, mock_save):
        self.sni.add_chall(self.achalls[0])
        responses = self.sni.perform()
        self.assertEqual([], responses)
        self.assertEqual(mock_save.call_count, 2)

    def test_setup_challenge_cert(self):
        # This is a helper function that can be used for handling
        # open context managers more elegantly. It avoids dealing with
        # __enter__ and __exit__ calls.
        # http://www.voidspace.org.uk/python/mock/helpers.html#mock.mock_open
        pass

    @mock.patch("letsencrypt_nginx.configurator.NginxConfigurator.save")
    def test_perform1(self, mock_save):
        self.sni.add_chall(self.achalls[1])
        responses = self.sni.perform()
        self.assertEqual(None, responses)
        self.assertEqual(mock_save.call_count, 1)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
