"""Tests for letsencrypt.client.auth_handler."""
import logging
import unittest

import mock

from letsencrypt import acme

from letsencrypt.client import challenge_util
from letsencrypt.client import errors
from letsencrypt.client.tests import acme_util



TRANSLATE = {
    "dvsni": "DvsniChall",
    "simpleHttps": "SimpleHttpsChall",
    "dns": "DnsChall",
    "recoveryToken": "RecTokenChall",
    "recoveryContact": "RecContactChall",
    "proofOfPossession": "PopChall",
}


class SatisfyChallengesTest(unittest.TestCase):
    """verify_identities test."""

    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler

        self.mock_dv_auth = mock.MagicMock(name='ApacheConfigurator')
        self.mock_client_auth = mock.MagicMock(name='ClientAuthenticator')

        self.mock_dv_auth.get_chall_pref.return_value = ["dvsni"]
        self.mock_client_auth.get_chall_pref.return_value = ["recoveryToken"]

        self.mock_client_auth.perform.side_effect = gen_auth_resp
        self.mock_dv_auth.perform.side_effect = gen_auth_resp

        self.handler = AuthHandler(
            self.mock_dv_auth, self.mock_client_auth, None)

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_name1_dvsni1(self):
        dom = "0"
        challenge = [acme_util.CHALLENGES["dvsni"]]
        msg = acme.messages.Challenge(session_id=dom, nonce="nonce0",
                                      challenges=challenge, combinations=[])
        self.handler.add_chall_msg(dom, msg, "dummy_key")

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 1)
        self.assertEqual(len(self.handler.responses[dom]), 1)

        self.assertEqual("DvsniChall0", self.handler.responses[dom][0])
        self.assertEqual(len(self.handler.dv_c), 1)
        self.assertEqual(len(self.handler.client_c), 1)
        self.assertEqual(len(self.handler.dv_c[dom]), 1)
        self.assertEqual(len(self.handler.client_c[dom]), 0)

    def test_name5_dvsni5(self):
        challenge = [acme_util.CHALLENGES["dvsni"]]
        for i in xrange(5):
            self.handler.add_chall_msg(
                str(i),
                acme.messages.Challenge(session_id=str(i), nonce="nonce%d" % i,
                                        challenges=challenge, combinations=[]),
                "dummy_key")

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 5)
        self.assertEqual(len(self.handler.dv_c), 5)
        self.assertEqual(len(self.handler.client_c), 5)
        # Each message contains 1 auth, 0 client

        for i in xrange(5):
            dom = str(i)
            self.assertEqual(len(self.handler.responses[dom]), 1)
            self.assertEqual(self.handler.responses[dom][0], "DvsniChall%d" % i)
            self.assertEqual(len(self.handler.dv_c[dom]), 1)
            self.assertEqual(len(self.handler.client_c[dom]), 0)
            self.assertTrue(isinstance(self.handler.dv_c[dom][0].chall,
                                       challenge_util.DvsniChall))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name1_auth(self, mock_chall_path):
        dom = "0"

        challenges = acme_util.get_dv_challenges()
        combos = acme_util.gen_combos(challenges)
        self.handler.add_chall_msg(
            dom,
            acme.messages.Challenge(session_id="0", nonce="nonce0",
                                    challenges=challenges, combinations=combos),
            "dummy_key")

        path = gen_path(["simpleHttps"], challenges)
        mock_chall_path.return_value = path
        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 1)
        self.assertEqual(len(self.handler.responses[dom]), len(challenges))
        self.assertEqual(len(self.handler.dv_c), 1)
        self.assertEqual(len(self.handler.client_c), 1)

        self.assertEqual(
            self.handler.responses[dom],
            self._get_exp_response(dom, path, challenges))

        self.assertEqual(len(self.handler.dv_c[dom]), 1)
        self.assertEqual(len(self.handler.client_c[dom]), 0)
        self.assertTrue(isinstance(self.handler.dv_c[dom][0].chall,
                                   challenge_util.SimpleHttpsChall))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name1_all(self, mock_chall_path):
        dom = "0"

        challenges = acme_util.get_challenges()
        combos = acme_util.gen_combos(challenges)
        self.handler.add_chall_msg(
            dom,
            acme.messages.Challenge(session_id=dom, nonce="nonce0",
                                    challenges=challenges, combinations=combos),
            "dummy_key")

        path = gen_path(["simpleHttps", "recoveryToken"], challenges)
        mock_chall_path.return_value = path

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 1)
        self.assertEqual(len(self.handler.responses[dom]), len(challenges))
        self.assertEqual(len(self.handler.dv_c), 1)
        self.assertEqual(len(self.handler.client_c), 1)
        self.assertEqual(len(self.handler.dv_c[dom]), 1)
        self.assertEqual(len(self.handler.client_c[dom]), 1)

        self.assertEqual(
            self.handler.responses[dom],
            self._get_exp_response(dom, path, challenges))
        self.assertTrue(isinstance(self.handler.dv_c[dom][0].chall,
                                   challenge_util.SimpleHttpsChall))
        self.assertTrue(isinstance(self.handler.client_c[dom][0].chall,
                                   challenge_util.RecTokenChall))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name5_all(self, mock_chall_path):
        challenges = acme_util.get_challenges()
        combos = acme_util.gen_combos(challenges)
        for i in xrange(5):
            self.handler.add_chall_msg(
                str(i),
                acme.messages.Challenge(
                    session_id=str(i), nonce="nonce%d" % i,
                    challenges=challenges, combinations=combos),
                "dummy_key")

        path = gen_path(["dvsni", "recoveryContact"], challenges)
        mock_chall_path.return_value = path

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 5)
        for i in xrange(5):
            self.assertEqual(
                len(self.handler.responses[str(i)]), len(challenges))
        self.assertEqual(len(self.handler.dv_c), 5)
        self.assertEqual(len(self.handler.client_c), 5)

        for i in range(5):
            dom = str(i)
            self.assertEqual(
                self.handler.responses[dom],
                self._get_exp_response(dom, path, challenges))
            self.assertEqual(len(self.handler.dv_c[dom]), 1)
            self.assertEqual(len(self.handler.client_c[dom]), 1)

            self.assertTrue(isinstance(self.handler.dv_c[dom][0].chall,
                                       challenge_util.DvsniChall))
            self.assertTrue(isinstance(self.handler.client_c[dom][0].chall,
                                       challenge_util.RecContactChall))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name5_mix(self, mock_chall_path):
        paths = []
        chosen_chall = [["dns"],
                        ["dvsni"],
                        ["simpleHttps", "proofOfPossession"],
                        ["simpleHttps"],
                        ["dns", "recoveryToken"]]
        challenge_list = [acme_util.get_dv_challenges(),
                          [acme_util.CHALLENGES["dvsni"]],
                          acme_util.get_challenges(),
                          acme_util.get_dv_challenges(),
                          acme_util.get_challenges()]

        # Combos doesn't matter since I am overriding the gen_path function
        for i in xrange(5):
            dom = str(i)
            paths.append(gen_path(chosen_chall[i], challenge_list[i]))
            self.handler.add_chall_msg(
                dom,
                acme.messages.Challenge(
                    session_id=dom, nonce="nonce%d" % i,
                    challenges=challenge_list[i], combinations=[]),
                "dummy_key")

        mock_chall_path.side_effect = paths

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 5)
        self.assertEqual(len(self.handler.dv_c), 5)
        self.assertEqual(len(self.handler.client_c), 5)

        for i in xrange(5):
            dom = str(i)
            resp = self._get_exp_response(i, paths[i], challenge_list[i])
            self.assertEqual(self.handler.responses[dom], resp)
            self.assertEqual(len(self.handler.dv_c[dom]), 1)
            self.assertEqual(
                len(self.handler.client_c[dom]), len(chosen_chall[i]) - 1)

        self.assertTrue(isinstance(self.handler.dv_c["0"][0].chall,
                                   challenge_util.DnsChall))
        self.assertTrue(isinstance(self.handler.dv_c["1"][0].chall,
                                   challenge_util.DvsniChall))
        self.assertTrue(isinstance(self.handler.dv_c["2"][0].chall,
                                   challenge_util.SimpleHttpsChall))
        self.assertTrue(isinstance(self.handler.dv_c["3"][0].chall,
                                   challenge_util.SimpleHttpsChall))
        self.assertTrue(isinstance(self.handler.dv_c["4"][0].chall,
                                   challenge_util.DnsChall))

        self.assertTrue(isinstance(self.handler.client_c["2"][0].chall,
                                   challenge_util.PopChall))
        self.assertTrue(isinstance(self.handler.client_c["4"][0].chall,
                                   challenge_util.RecTokenChall))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_perform_exception_cleanup(self, mock_chall_path):
        """3 Challenge messages... fail perform... clean up."""
        # pylint: disable=protected-access
        self.mock_dv_auth.perform.side_effect = errors.LetsEncryptDvsniError

        challenges = acme_util.get_challenges()
        combos = acme_util.gen_combos(challenges)

        for i in xrange(3):
            self.handler.add_chall_msg(
                str(i),
                acme.messages.Challenge(
                    session_id=str(i), nonce="nonce%d" % i,
                    challenges=challenges, combinations=combos),
                "dummy_key")

        mock_chall_path.return_value = gen_path(
            ["dvsni", "proofOfPossession"], challenges)

        # This may change in the future... but for now catch the error
        self.assertRaises(errors.LetsEncryptAuthHandlerError,
                          self.handler._satisfy_challenges)

        # Verify cleanup is actually run correctly
        self.assertEqual(self.mock_dv_auth.cleanup.call_count, 3)
        self.assertEqual(self.mock_client_auth.cleanup.call_count, 3)

        # Check DV cleanup
        mock_cleanup_args = self.mock_dv_auth.cleanup.call_args_list
        for i in xrange(3):
            # Assert length of arg list was 1
            arg_chall_list = mock_cleanup_args[i][0][0]
            self.assertEqual(len(arg_chall_list), 1)
            self.assertTrue(isinstance(arg_chall_list[0],
                                       challenge_util.DvsniChall))

        # Check Auth cleanup
        mock_cleanup_args = self.mock_client_auth.cleanup.call_args_list
        for i in xrange(3):
            arg_chall_list = mock_cleanup_args[i][0][0]
            self.assertEqual(len(arg_chall_list), 1)
            self.assertTrue(isinstance(arg_chall_list[0],
                                       challenge_util.PopChall))


    def _get_exp_response(self, domain, path, challenges):
        # pylint: disable=no-self-use
        exp_resp = ["null"] * len(challenges)
        for i in path:
            exp_resp[i] = TRANSLATE[challenges[i]["type"]] + str(domain)

        return exp_resp


# pylint: disable=protected-access
class GetAuthorizationsTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler

        self.mock_dv_auth = mock.MagicMock(name='ApacheConfigurator')
        self.mock_client_auth = mock.MagicMock(name='ClientAuthenticator')

        self.mock_sat_chall = mock.MagicMock(name="_satisfy_challenges")
        self.mock_acme_auth = mock.MagicMock(name="acme_authorization")

        self.iteration = 0

        self.handler = AuthHandler(
            self.mock_dv_auth, self.mock_client_auth, None)

        self.handler._satisfy_challenges = self.mock_sat_chall
        self.handler.acme_authorization = self.mock_acme_auth

    def test_solved3_at_once(self):
        # Set 3 DVSNI challenges
        challenge = [acme_util.CHALLENGES["dvsni"]]
        for i in xrange(3):
            self.handler.add_chall_msg(
                str(i),
                acme.messages.Challenge(session_id=str(i), nonce="nonce%d" % i,
                                        challenges=challenge, combinations=[]),
                "dummy_key")

        self.mock_sat_chall.side_effect = self._sat_solved_at_once
        self.handler.get_authorizations()

        self.assertEqual(self.mock_sat_chall.call_count, 1)
        self.assertEqual(self.mock_acme_auth.call_count, 3)

        exp_call_list = [mock.call("0"), mock.call("1"), mock.call("2")]
        self.assertEqual(
            self.mock_acme_auth.call_args_list, exp_call_list)
        self._test_finished()

    def _sat_solved_at_once(self):
        for i in xrange(3):
            dom = str(i)
            self.handler.responses[dom] = ["DvsniChall%d" % i]
            self.handler.paths[dom] = [0]
            # Assignment was > 80 char...
            dv_c, c_c = self.handler._challenge_factory(dom, [0])

            self.handler.dv_c[dom], self.handler.client_c[dom] = dv_c, c_c

    def test_progress_failure(self):
        challenges = acme_util.get_challenges()
        self.handler.add_chall_msg(
            "0",
            acme.messages.Challenge(session_id="0", nonce="nonce0",
                                    challenges=challenges, combinations=[]),
            "dummy_key")

        # Don't do anything to satisfy challenges
        self.mock_sat_chall.side_effect = self._sat_failure

        self.assertRaises(
            errors.LetsEncryptAuthHandlerError, self.handler.get_authorizations)

        # Check to make sure program didn't loop
        self.assertEqual(self.mock_sat_chall.call_count, 1)

    def _sat_failure(self):
        dom = "0"
        self.handler.paths[dom] = gen_path(
            ["dns", "recoveryToken"], self.handler.msgs[dom].challenges)
        dv_c, c_c = self.handler._challenge_factory(
            dom, self.handler.paths[dom])
        self.handler.dv_c[dom], self.handler.client_c[dom] = dv_c, c_c

    def test_incremental_progress(self):
        challs = []
        challs.append(acme_util.get_challenges())
        challs.append(acme_util.get_dv_challenges())
        for i in xrange(2):
            dom = str(i)
            self.handler.add_chall_msg(
                dom,
                acme.messages.Challenge(session_id=dom, nonce="nonce%d" % i,
                                        challenges=challs[i], combinations=[]),
                "dummy_key")

        self.mock_sat_chall.side_effect = self._sat_incremental

        self.handler.get_authorizations()

        self._test_finished()
        self.assertEqual(self.mock_acme_auth.call_args_list,
                         [mock.call("1"), mock.call("0")])

    def _sat_incremental(self):
        # Exact responses don't matter, just path/response match
        if self.iteration == 0:
            # Only solve one of "0" required challs
            self.handler.responses["0"][1] = "onecomplete"
            self.handler.responses["0"][3] = None
            self.handler.responses["1"] = ["null", "null", "goodresp"]
            self.handler.paths["0"] = [1, 3]
            self.handler.paths["1"] = [2]
            # This is probably overkill... but set it anyway
            dv_c, c_c = self.handler._challenge_factory("0", [1, 3])
            self.handler.dv_c["0"], self.handler.client_c["0"] = dv_c, c_c
            dv_c, c_c = self.handler._challenge_factory("1", [2])
            self.handler.dv_c["1"], self.handler.client_c["1"] = dv_c, c_c

            self.iteration += 1

        elif self.iteration == 1:
            # Quick check to make sure it was actually completed.
            self.assertEqual(
                self.mock_acme_auth.call_args_list, [mock.call("1")])
            self.handler.responses["0"][1] = "now_finish"
            self.handler.responses["0"][3] = "finally!"

        else:
            raise errors.LetsEncryptAuthHandlerError(
                "Failed incremental test: too many invocations")

    def _test_finished(self):
        self.assertFalse(self.handler.msgs)
        self.assertFalse(self.handler.dv_c)
        self.assertFalse(self.handler.responses)
        self.assertFalse(self.handler.paths)
        self.assertFalse(self.handler.domains)


# pylint: disable=protected-access
class PathSatisfiedTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler
        self.handler = AuthHandler(None, None, None)

    def test_satisfied_true(self):
        dom = ["0", "1", "2", "3", "4"]
        self.handler.paths[dom[0]] = [1, 2]
        self.handler.responses[dom[0]] = ["null", "sat", "sat2", "null"]

        self.handler.paths[dom[1]] = [0]
        self.handler.responses[dom[1]] = ["sat", None, None, "null"]

        self.handler.paths[dom[2]] = [0]
        self.handler.responses[dom[2]] = ["sat"]

        self.handler.paths[dom[3]] = []
        self.handler.responses[dom[3]] = []

        self.handler.paths[dom[4]] = []
        self.handler.responses[dom[4]] = ["respond... sure"]

        for i in xrange(5):
            self.assertTrue(self.handler._path_satisfied(dom[i]))

    def test_not_satisfied(self):
        dom = ["0", "1", "2", "3", "4"]
        self.handler.paths[dom[0]] = [1, 2]
        self.handler.responses[dom[0]] = ["sat1", "null", "sat2", "null"]

        self.handler.paths[dom[1]] = [0]
        self.handler.responses[dom[1]] = [None, "null", "null", "null"]

        self.handler.paths[dom[2]] = [0]
        self.handler.responses[dom[2]] = [None]

        self.handler.paths[dom[3]] = [0]
        self.handler.responses[dom[3]] = ["null"]

        for i in xrange(4):
            self.assertFalse(self.handler._path_satisfied(dom[i]))


def gen_auth_resp(chall_list):
    """Generate a dummy authorization response."""
    return ["%s%s" % (type(chall).__name__, chall.domain)
            for chall in chall_list]


def gen_path(str_list, challenges):
    """Generate a path for challenge messages

    :param list str_list: challenge message types (:class:`str`)
    :param dict challenges: ACME challenge messages

    :return: :class:`list` of :class:`int`

    """
    path = []
    for i, chall in enumerate(challenges):
        for str_chall in str_list:
            if chall["type"] == str_chall:
                path.append(i)
                continue
    return path


if __name__ == '__main__':
    unittest.main()
