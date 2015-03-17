"""Tests for letsencrypt.client.auth_handler."""
import logging
import unittest

import mock

from letsencrypt.acme import challenges
from letsencrypt.acme import messages

from letsencrypt.client import achallenges
from letsencrypt.client import errors

from letsencrypt.client.tests import acme_util


TRANSLATE = {
    "dvsni": "DVSNI",
    "simpleHttps": "SimpleHTTPS",
    "dns": "DNS",
    "recoveryToken": "RecoveryToken",
    "recoveryContact": "RecoveryContact",
    "proofOfPossession": "ProofOfPossession",
}


class SatisfyChallengesTest(unittest.TestCase):
    """verify_identities test."""

    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler

        self.mock_dv_auth = mock.MagicMock(name="ApacheConfigurator")
        self.mock_client_auth = mock.MagicMock(name="ClientAuthenticator")

        self.mock_dv_auth.get_chall_pref.return_value = [challenges.DVSNI]
        self.mock_client_auth.get_chall_pref.return_value = [
            challenges.RecoveryToken]

        self.mock_client_auth.perform.side_effect = gen_auth_resp
        self.mock_dv_auth.perform.side_effect = gen_auth_resp

        self.handler = AuthHandler(
            self.mock_dv_auth, self.mock_client_auth, None)

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_name1_dvsni1(self):
        dom = "0"
        msg = messages.Challenge(
            session_id=dom, nonce="nonce0", combinations=[],
            challenges=[acme_util.DVSNI])
        self.handler.add_chall_msg(dom, msg, "dummy_key")

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 1)
        self.assertEqual(len(self.handler.responses[dom]), 1)

        self.assertEqual("DVSNI0", self.handler.responses[dom][0])
        self.assertEqual(len(self.handler.dv_c), 1)
        self.assertEqual(len(self.handler.client_c), 1)
        self.assertEqual(len(self.handler.dv_c[dom]), 1)
        self.assertEqual(len(self.handler.client_c[dom]), 0)

    def test_name1_rectok1(self):
        dom = "0"
        msg = messages.Challenge(
            session_id=dom, nonce="nonce0", combinations=[],
            challenges=[acme_util.RECOVERY_TOKEN])
        self.handler.add_chall_msg(dom, msg, "dummy_key")

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 1)
        self.assertEqual(len(self.handler.responses[dom]), 1)

        # Test if statement for dv_auth perform
        self.assertEqual(self.mock_client_auth.perform.call_count, 1)
        self.assertEqual(self.mock_dv_auth.perform.call_count, 0)

        self.assertEqual("RecoveryToken0", self.handler.responses[dom][0])
        # Assert 1 domain
        self.assertEqual(len(self.handler.dv_c), 1)
        self.assertEqual(len(self.handler.client_c), 1)
        # Assert 1 auth challenge, 0 dv
        self.assertEqual(len(self.handler.dv_c[dom]), 0)
        self.assertEqual(len(self.handler.client_c[dom]), 1)

    def test_name5_dvsni5(self):
        for i in xrange(5):
            self.handler.add_chall_msg(
                str(i),
                messages.Challenge(session_id=str(i), nonce="nonce%d" % i,
                                   challenges=[acme_util.DVSNI],
                                   combinations=[]),
                "dummy_key")

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 5)
        self.assertEqual(len(self.handler.dv_c), 5)
        self.assertEqual(len(self.handler.client_c), 5)
        # Each message contains 1 auth, 0 client

        # Test proper call count for methods
        self.assertEqual(self.mock_client_auth.perform.call_count, 0)
        self.assertEqual(self.mock_dv_auth.perform.call_count, 1)

        for i in xrange(5):
            dom = str(i)
            self.assertEqual(len(self.handler.responses[dom]), 1)
            self.assertEqual(self.handler.responses[dom][0], "DVSNI%d" % i)
            self.assertEqual(len(self.handler.dv_c[dom]), 1)
            self.assertEqual(len(self.handler.client_c[dom]), 0)
            self.assertTrue(isinstance(self.handler.dv_c[dom][0].achall,
                                       achallenges.DVSNI))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name1_auth(self, mock_chall_path):
        dom = "0"

        self.handler.add_chall_msg(
            dom,
            messages.Challenge(
                session_id="0", nonce="nonce0",
                challenges=acme_util.DV_CHALLENGES,
                combinations=acme_util.gen_combos(acme_util.DV_CHALLENGES)),
            "dummy_key")

        path = gen_path([acme_util.SIMPLE_HTTPS], acme_util.DV_CHALLENGES)
        mock_chall_path.return_value = path
        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 1)
        self.assertEqual(len(self.handler.responses[dom]),
                         len(acme_util.DV_CHALLENGES))
        self.assertEqual(len(self.handler.dv_c), 1)
        self.assertEqual(len(self.handler.client_c), 1)

        # Test if statement for client_auth perform
        self.assertEqual(self.mock_client_auth.perform.call_count, 0)
        self.assertEqual(self.mock_dv_auth.perform.call_count, 1)

        self.assertEqual(
            self.handler.responses[dom],
            self._get_exp_response(dom, path, acme_util.DV_CHALLENGES))

        self.assertEqual(len(self.handler.dv_c[dom]), 1)
        self.assertEqual(len(self.handler.client_c[dom]), 0)
        self.assertTrue(isinstance(self.handler.dv_c[dom][0].achall,
                                   achallenges.SimpleHTTPS))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name1_all(self, mock_chall_path):
        dom = "0"

        combos = acme_util.gen_combos(acme_util.CHALLENGES)
        self.handler.add_chall_msg(
            dom,
            messages.Challenge(
                session_id=dom, nonce="nonce0", challenges=acme_util.CHALLENGES,
                combinations=combos),
            "dummy_key")

        path = gen_path([acme_util.SIMPLE_HTTPS, acme_util.RECOVERY_TOKEN],
                        acme_util.CHALLENGES)
        mock_chall_path.return_value = path

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 1)
        self.assertEqual(
            len(self.handler.responses[dom]), len(acme_util.CHALLENGES))
        self.assertEqual(len(self.handler.dv_c), 1)
        self.assertEqual(len(self.handler.client_c), 1)
        self.assertEqual(len(self.handler.dv_c[dom]), 1)
        self.assertEqual(len(self.handler.client_c[dom]), 1)

        self.assertEqual(
            self.handler.responses[dom],
            self._get_exp_response(dom, path, acme_util.CHALLENGES))
        self.assertTrue(isinstance(self.handler.dv_c[dom][0].achall,
                                   achallenges.SimpleHTTPS))
        self.assertTrue(isinstance(self.handler.client_c[dom][0].achall,
                                   achallenges.RecoveryToken))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name5_all(self, mock_chall_path):
        combos = acme_util.gen_combos(acme_util.CHALLENGES)
        for i in xrange(5):
            self.handler.add_chall_msg(
                str(i),
                messages.Challenge(
                    session_id=str(i), nonce="nonce%d" % i,
                    challenges=acme_util.CHALLENGES, combinations=combos),
                "dummy_key")

        path = gen_path([acme_util.DVSNI, acme_util.RECOVERY_CONTACT],
                        acme_util.CHALLENGES)
        mock_chall_path.return_value = path

        self.handler._satisfy_challenges()  # pylint: disable=protected-access

        self.assertEqual(len(self.handler.responses), 5)
        for i in xrange(5):
            self.assertEqual(
                len(self.handler.responses[str(i)]), len(acme_util.CHALLENGES))
        self.assertEqual(len(self.handler.dv_c), 5)
        self.assertEqual(len(self.handler.client_c), 5)

        for i in xrange(5):
            dom = str(i)
            self.assertEqual(
                self.handler.responses[dom],
                self._get_exp_response(dom, path, acme_util.CHALLENGES))
            self.assertEqual(len(self.handler.dv_c[dom]), 1)
            self.assertEqual(len(self.handler.client_c[dom]), 1)

            self.assertTrue(isinstance(self.handler.dv_c[dom][0].achall,
                                       achallenges.DVSNI))
            self.assertTrue(isinstance(self.handler.client_c[dom][0].achall,
                                       achallenges.RecoveryContact))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_name5_mix(self, mock_chall_path):
        paths = []
        chosen_chall = [[acme_util.DNS],
                        [acme_util.DVSNI],
                        [acme_util.SIMPLE_HTTPS, acme_util.POP],
                        [acme_util.SIMPLE_HTTPS],
                        [acme_util.DNS, acme_util.RECOVERY_TOKEN]]
        challenge_list = [acme_util.DV_CHALLENGES,
                          [acme_util.DVSNI],
                          acme_util.CHALLENGES,
                          acme_util.DV_CHALLENGES,
                          acme_util.CHALLENGES]

        # Combos doesn't matter since I am overriding the gen_path function
        for i in xrange(5):
            dom = str(i)
            paths.append(gen_path(chosen_chall[i], challenge_list[i]))
            self.handler.add_chall_msg(
                dom,
                messages.Challenge(
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

        self.assertTrue(isinstance(
            self.handler.dv_c["0"][0].achall, achallenges.DNS))
        self.assertTrue(isinstance(
            self.handler.dv_c["1"][0].achall, achallenges.DVSNI))
        self.assertTrue(isinstance(
            self.handler.dv_c["2"][0].achall, achallenges.SimpleHTTPS))
        self.assertTrue(isinstance(
            self.handler.dv_c["3"][0].achall, achallenges.SimpleHTTPS))
        self.assertTrue(isinstance(
            self.handler.dv_c["4"][0].achall, achallenges.DNS))

        self.assertTrue(isinstance(self.handler.client_c["2"][0].achall,
                                   achallenges.ProofOfPossession))
        self.assertTrue(isinstance(
            self.handler.client_c["4"][0].achall, achallenges.RecoveryToken))

    @mock.patch("letsencrypt.client.auth_handler.gen_challenge_path")
    def test_perform_exception_cleanup(self, mock_chall_path):
        """3 Challenge messages... fail perform... clean up."""
        # pylint: disable=protected-access
        self.mock_dv_auth.perform.side_effect = errors.LetsEncryptDvsniError

        combos = acme_util.gen_combos(acme_util.CHALLENGES)

        for i in xrange(3):
            self.handler.add_chall_msg(
                str(i),
                messages.Challenge(
                    session_id=str(i), nonce="nonce%d" % i,
                    challenges=acme_util.CHALLENGES, combinations=combos),
                "dummy_key")

        mock_chall_path.side_effect = [
            gen_path([acme_util.DVSNI, acme_util.POP], acme_util.CHALLENGES),
            gen_path([acme_util.POP], acme_util.CHALLENGES),
            gen_path([acme_util.DVSNI], acme_util.CHALLENGES),
        ]

        # This may change in the future... but for now catch the error
        self.assertRaises(errors.LetsEncryptAuthHandlerError,
                          self.handler._satisfy_challenges)

        # Verify cleanup is actually run correctly
        self.assertEqual(self.mock_dv_auth.cleanup.call_count, 2)
        self.assertEqual(self.mock_client_auth.cleanup.call_count, 2)


        dv_cleanup_args = self.mock_dv_auth.cleanup.call_args_list
        client_cleanup_args = self.mock_client_auth.cleanup.call_args_list

        # Check DV cleanup
        for i in xrange(2):
            dv_chall_list = dv_cleanup_args[i][0][0]
            self.assertEqual(len(dv_chall_list), 1)
            self.assertTrue(
                isinstance(dv_chall_list[0], achallenges.DVSNI))


        # Check Auth cleanup
        for i in xrange(2):
            client_chall_list = client_cleanup_args[i][0][0]
            self.assertEqual(len(client_chall_list), 1)
            self.assertTrue(
                isinstance(client_chall_list[0], achallenges.ProofOfPossession))


    def _get_exp_response(self, domain, path, challs):
        # pylint: disable=no-self-use
        exp_resp = [None] * len(challs)
        for i in path:
            exp_resp[i] = TRANSLATE[challs[i].typ] + str(domain)

        return exp_resp


# pylint: disable=protected-access
class GetAuthorizationsTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler

        self.mock_dv_auth = mock.MagicMock(name="ApacheConfigurator")
        self.mock_client_auth = mock.MagicMock(name="ClientAuthenticator")

        self.mock_sat_chall = mock.MagicMock(name="_satisfy_challenges")
        self.mock_acme_auth = mock.MagicMock(name="acme_authorization")

        self.iteration = 0

        self.handler = AuthHandler(
            self.mock_dv_auth, self.mock_client_auth, None)

        self.handler._satisfy_challenges = self.mock_sat_chall
        self.handler.acme_authorization = self.mock_acme_auth

    def test_solved3_at_once(self):
        # Set 3 DVSNI challenges
        for i in xrange(3):
            self.handler.add_chall_msg(
                str(i),
                messages.Challenge(
                    session_id=str(i), nonce="nonce%d" % i,
                    challenges=[acme_util.DVSNI], combinations=[]),
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
            self.handler.responses[dom] = ["DVSNI%d" % i]
            self.handler.paths[dom] = [0]
            # Assignment was > 80 char...
            dv_c, c_c = self.handler._challenge_factory(dom, [0])

            self.handler.dv_c[dom], self.handler.client_c[dom] = dv_c, c_c

    def test_progress_failure(self):
        self.handler.add_chall_msg(
            "0",
            messages.Challenge(
                session_id="0", nonce="nonce0", challenges=acme_util.CHALLENGES,
                combinations=[]),
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
            [acme_util.DNS, acme_util.RECOVERY_TOKEN],
            self.handler.msgs[dom].challenges)
        dv_c, c_c = self.handler._challenge_factory(
            dom, self.handler.paths[dom])
        self.handler.dv_c[dom], self.handler.client_c[dom] = dv_c, c_c

    def test_incremental_progress(self):
        for dom, challs in [("0", acme_util.CHALLENGES),
                            ("1", acme_util.DV_CHALLENGES)]:
            self.handler.add_chall_msg(
                dom,
                messages.Challenge(session_id=dom, nonce="nonce",
                                   combinations=[], challenges=challs),
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
            self.handler.responses["1"] = [None, None, "goodresp"]
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
        self.handler.responses[dom[0]] = [None, "sat", "sat2", None]

        self.handler.paths[dom[1]] = [0]
        self.handler.responses[dom[1]] = ["sat", None, None, None]

        self.handler.paths[dom[2]] = [0]
        self.handler.responses[dom[2]] = ["sat"]

        self.handler.paths[dom[3]] = []
        self.handler.responses[dom[3]] = []

        self.handler.paths[dom[4]] = []
        self.handler.responses[dom[4]] = ["respond... sure"]

        for i in xrange(5):
            self.assertTrue(self.handler._path_satisfied(dom[i]))

    def test_not_satisfied(self):
        dom = ["0", "1", "2"]
        self.handler.paths[dom[0]] = [1, 2]
        self.handler.responses[dom[0]] = ["sat1", None, "sat2", None]

        self.handler.paths[dom[1]] = [0]
        self.handler.responses[dom[1]] = [None, None, None, None]

        self.handler.paths[dom[2]] = [0]
        self.handler.responses[dom[2]] = [None]

        for i in xrange(3):
            self.assertFalse(self.handler._path_satisfied(dom[i]))


class MutuallyExclusiveTest(unittest.TestCase):
    """Tests for letsencrypt.client.auth_handler.mutually_exclusive."""

    # pylint: disable=invalid-name,missing-docstring,too-few-public-methods
    class A(object):
        pass

    class B(object):
        pass

    class C(object):
        pass

    class D(C):
        pass

    @classmethod
    def _call(cls, chall1, chall2, different=False):
        from letsencrypt.client.auth_handler import mutually_exclusive
        return mutually_exclusive(chall1, chall2, groups=frozenset([
            frozenset([cls.A, cls.B]), frozenset([cls.A, cls.C]),
        ]), different=different)

    def test_group_members(self):
        self.assertFalse(self._call(self.A(), self.B()))
        self.assertFalse(self._call(self.A(), self.C()))

    def test_cross_group(self):
        self.assertTrue(self._call(self.B(), self.C()))

    def test_same_type(self):
        self.assertFalse(self._call(self.A(), self.A(), different=False))
        self.assertTrue(self._call(self.A(), self.A(), different=True))

        # in particular...
        obj = self.A()
        self.assertFalse(self._call(obj, obj, different=False))
        self.assertTrue(self._call(obj, obj, different=True))

    def test_subclass(self):
        self.assertFalse(self._call(self.A(), self.D()))
        self.assertFalse(self._call(self.D(), self.A()))


class IsPreferredTest(unittest.TestCase):
    """Tests for letsencrypt.client.auth_handler.is_preferred."""

    @classmethod
    def _call(cls, chall, satisfied):
        from letsencrypt.client.auth_handler import is_preferred
        return is_preferred(chall, satisfied, exclusive_groups=frozenset([
            frozenset([challenges.DVSNI, challenges.SimpleHTTPS]),
            frozenset([challenges.DNS, challenges.SimpleHTTPS]),
        ]))

    def test_empty_satisfied(self):
        self.assertTrue(self._call(acme_util.DNS, frozenset()))

    def test_mutually_exclusvie(self):
        self.assertFalse(
            self._call(acme_util.DVSNI, frozenset([acme_util.SIMPLE_HTTPS])))

    def test_mutually_exclusive_same_type(self):
        self.assertTrue(
            self._call(acme_util.DVSNI, frozenset([acme_util.DVSNI])))


def gen_auth_resp(chall_list):
    """Generate a dummy authorization response."""
    return ["%s%s" % (chall.__class__.__name__, chall.domain)
            for chall in chall_list]


def gen_path(required, challs):
    """Generate a combination by picking ``required`` from ``challs``.

    :param required: Required types of challenges (subclasses of
        :class:`~letsencrypt.acme.challenges.Challenge`).
    :param challs: Sequence of ACME challenge messages, corresponding to
        :attr:`letsencrypt.acme.messages.Challenge.challenges`.

    :return: :class:`list` of :class:`int`

    """
    return [challs.index(chall) for chall in required]

if __name__ == "__main__":
    unittest.main()
