"""Test client.py."""
import unittest
import mock
import pkg_resources

from letsencrypt.client.tests import acme_util


class VerifyIdentityTest(unittest.TestCase):
    """verify_identities test."""
    def setUp(self):
        from letsencrypt.client.client import Client
        from letsencrypt.client import CONFIG

        rsa256_file = pkg_resources.resource_filename(
            __name__, 'testdata/rsa256_key.pem')
        rsa256_pem = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')

        auth_key = Client.Key(rsa256_file, rsa256_pem)

        self.mock_auth = mock.MagicMock(name='ApacheConfigurator')
        self.mock_auth.get_chall_pref.return_value = ["dvsni"]
        self.mock_auth.perform.side_effect = gen_auth_resp

        self.client = Client(
            CONFIG.ACME_SERVER, ["0", "1", "2", "3", "4"],
            auth_key, self.mock_auth, None)
        self.client.perform = mock.MagicMock(
            name='perform', side_effect=gen_auth_resp)

    def test_name1_dvsni1(self):
        self.client.names = ["0"]
        challenge = [acme_util.CHALLENGES["dvsni"]]
        msgs = [acme_util.get_chall_msg("0", "nonce0", challenge)]

        responses, auth_c, client_c = self.client.verify_identities(msgs)

        self.assertEqual(len(responses), 1)
        self.assertEqual(len(responses[0]), 1)

        self.assertEqual("DvsniChall0", responses[0][0])
        self.assertEqual(len(auth_c), 1)
        self.assertEqual(len(client_c), 1)
        self.assertEqual(len(auth_c[0]), 1)
        self.assertEqual(len(client_c[0]), 0)

    def test_name5_dvsni5(self):
        challenge = [acme_util.CHALLENGES["dvsni"]]
        msgs = []
        for i in range(5):
            msgs.append(
                acme_util.get_chall_msg(str(i), "nonce%d" % i, challenge))

        responses, auth_c, client_c = self.client.verify_identities(msgs)

        self.assertEqual(len(responses), 5)
        self.assertEqual(len(auth_c), 5)
        self.assertEqual(len(client_c), 5)
        # Each message contains 1 auth, 0 client
        for i in range(5):
            self.assertEqual(len(responses[i]), 1)
            self.assertEqual(responses[i][0], "DvsniChall%d" % i)
            self.assertEqual(len(auth_c[i]), 1)
            self.assertEqual(len(client_c[i]), 0)
            self.assertEqual(type(auth_c[i][0]).__name__, "DvsniChall")

    @mock.patch("letsencrypt.client.client."
                "challenge.gen_challenge_path")
    def test_name1_auth(self, mock_chall_path):
        self.client.names = ["0"]

        challenges = acme_util.get_auth_challenges()
        combos = acme_util.gen_combos(challenges)
        msgs = [acme_util.get_chall_msg("0", "nonce0", challenges, combos)]

        path = gen_path(["simpleHttps"], challenges)
        mock_chall_path.return_value = path

        responses, auth_c, client_c = self.client.verify_identities(msgs)

        self.assertEqual(len(responses), 1)
        self.assertEqual(len(responses[0]), len(challenges))
        self.assertEqual(len(auth_c), 1)
        self.assertEqual(len(client_c), 1)

        self.assertEqual(
            responses[0],
            self._get_exp_response("0", path, challenges))

        self.assertEqual(len(auth_c[0]), 1)
        self.assertEqual(len(client_c[0]), 0)
        self.assertEqual(type(auth_c[0][0]).__name__, "SimpleHttpsChall")

    @mock.patch("letsencrypt.client.client."
                "challenge.gen_challenge_path")
    def test_name1_all(self, mock_chall_path):
        self.client.names = ["0"]

        challenges = acme_util.get_challenges()
        combos = acme_util.gen_combos(challenges)
        msgs = [acme_util.get_chall_msg("0", "nonce0", challenges, combos)]

        path = gen_path(["simpleHttps", "recoveryToken"], challenges)
        mock_chall_path.return_value = path

        responses, auth_c, client_c = self.client.verify_identities(msgs)

        self.assertEqual(len(responses), 1)
        self.assertEqual(len(responses[0]), len(challenges))
        self.assertEqual(len(auth_c), 1)
        self.assertEqual(len(client_c), 1)
        self.assertEqual(len(auth_c[0]), 1)
        self.assertEqual(len(client_c[0]), 1)

        self.assertEqual(
            responses[0],
            self._get_exp_response("0", path, challenges))
        self.assertEqual(type(auth_c[0][0]).__name__, "SimpleHttpsChall")
        self.assertEqual(type(client_c[0][0]).__name__, "RecTokenChall")

    @mock.patch("letsencrypt.client.client."
                "challenge.gen_challenge_path")
    def test_name5_all(self, mock_chall_path):
        challenges = acme_util.get_challenges()
        combos = acme_util.gen_combos(challenges)
        msgs = []
        for i in range(5):
            msgs.append(
                acme_util.get_chall_msg(
                    str(i), "nonce%d" % i, challenges, combos))

        path = gen_path(["dvsni", "recoveryContact"], challenges)
        mock_chall_path.return_value = path

        responses, auth_c, client_c = self.client.verify_identities(msgs)

        self.assertEqual(len(responses), 5)
        for i in range(5):
            self.assertEqual(len(responses[i]), len(challenges))
        self.assertEqual(len(auth_c), 5)
        self.assertEqual(len(client_c), 5)

        for i in range(5):
            self.assertEqual(
                responses[i], self._get_exp_response(i, path, challenges))
            self.assertEqual(len(auth_c[0]), 1)
            self.assertEqual(len(client_c[0]), 1)

            self.assertEqual(type(auth_c[i][0]).__name__, "DvsniChall")
            self.assertEqual(type(client_c[i][0]).__name__, "RecContactChall")

    @mock.patch("letsencrypt.client.client."
                "challenge.gen_challenge_path")
    def test_name5_mix(self, mock_chall_path):
        paths = []
        msgs = []
        chosen_chall = [["dns"],
                        ["dvsni"],
                        ["simpleHttps", "proofOfPossession"],
                        ["simpleHttps"],
                        ["dns", "recoveryToken"]]
        challenge_list = [acme_util.get_auth_challenges(),
                          [acme_util.CHALLENGES["dvsni"]],
                          acme_util.get_challenges(),
                          acme_util.get_auth_challenges(),
                          acme_util.get_challenges()]

        # Combos doesn't matter since I am overriding the gen_path function
        for i in range(5):
            paths.append(gen_path(chosen_chall[i], challenge_list[i]))
            msgs.append(
                acme_util.get_chall_msg(
                    str(i), "nonce%d" % i, challenge_list[i]))

        mock_chall_path.side_effect = paths

        responses, auth_c, client_c = self.client.verify_identities(msgs)

        self.assertEqual(len(responses), 5)
        self.assertEqual(len(auth_c), 5)
        self.assertEqual(len(client_c), 5)

        for i in range(5):
            resp = self._get_exp_response(i, paths[i], challenge_list[i])
            self.assertEqual(responses[i], resp)
            self.assertEqual(len(auth_c[i]), 1)
            self.assertEqual(len(client_c[i]), len(chosen_chall[i]) - 1)

        self.assertEqual(type(auth_c[0][0]).__name__, "DnsChall")
        self.assertEqual(type(auth_c[1][0]).__name__, "DvsniChall")
        self.assertEqual(type(auth_c[2][0]).__name__, "SimpleHttpsChall")
        self.assertEqual(type(auth_c[3][0]).__name__, "SimpleHttpsChall")
        self.assertEqual(type(auth_c[4][0]).__name__, "DnsChall")

        self.assertEqual(type(client_c[2][0]).__name__, "PopChall")
        self.assertEqual(type(client_c[4][0]).__name__, "RecTokenChall")

    def _get_exp_response(self, domain, path, challenges):
        exp_resp = ["null"] * len(challenges)
        for i in path:
            exp_resp[i] = translate[challenges[i]["type"]] + str(domain)

        return exp_resp


class ClientPerformTest(unittest.TestCase):
    """Test client perform function."""
    def setUp(self):
        from letsencrypt.client.client import Client
        from letsencrypt.client import CONFIG

        rsa256_file = pkg_resources.resource_filename(
            __name__, 'testdata/rsa256_key.pem')
        rsa256_pem = pkg_resources.resource_string(
            __name__, 'testdata/rsa256_key.pem')

        auth_key = Client.Key(rsa256_file, rsa256_pem)

        self.client = Client(
            CONFIG.ACME_SERVER,  ["example.com"], auth_key, None, None)
        self.client.rec_token.perform = mock.MagicMock(
            name="rec_token_perform", side_effect=gen_client_resp)

    def test_rec_token1(self):
        from letsencrypt.client.challenge_util import RecTokenChall
        token = RecTokenChall("0")

        responses = self.client.perform([token])

        self.assertEqual(responses, ["RecTokenChall0"])

    def test_rec_token5(self):
        from letsencrypt.client.challenge_util import RecTokenChall
        tokens = []
        for i in range(5):
            tokens.append(RecTokenChall(str(i)))

        responses = self.client.perform(tokens)

        self.assertEqual(len(responses), 5)
        for i in range(5):
            self.assertEqual(responses[i], "RecTokenChall%d" % i)

    def test_unexpected(self):
        from letsencrypt.client.challenge_util import DvsniChall
        from letsencrypt.client.errors import LetsEncryptClientError
        unexpected = DvsniChall("0", "rb64", "123", "invalid_key")

        self.assertRaises(
            LetsEncryptClientError, self.client.perform, [unexpected])


translate = {"dvsni": "DvsniChall",
             "simpleHttps": "SimpleHttpsChall",
             "dns": "DnsChall",
             "recoveryToken": "RecTokenChall",
             "recoveryContact": "RecContactChall",
             "proofOfPossession": "PopChall"}


def gen_auth_resp(chall_list):
    return ["%s%s" % (type(chall).__name__, chall.domain)
            for chall in chall_list]


def gen_client_resp(chall):
    return "%s%s" % (type(chall).__name__, chall.domain)


def gen_path(str_list, challenges):
    path = []
    for i, chall in enumerate(challenges):
        for str_chall in str_list:
            if chall["type"] == str_chall:
                path.append(i)
                continue
    return path


if __name__ == '__main__':
    unittest.main()
