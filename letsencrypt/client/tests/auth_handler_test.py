"""Tests for letsencrypt.client.auth_handler."""
import functools
import logging
import unittest

import mock

from letsencrypt.acme import challenges

from letsencrypt.client import errors
from letsencrypt.client import le_util
from letsencrypt.client import network2

from letsencrypt.client.tests import acme_util


TRANSLATE = {
    "dvsni": "DVSNI",
    "simpleHttps": "SimpleHTTPS",
    "dns": "DNS",
    "recoveryToken": "RecoveryToken",
    "recoveryContact": "RecoveryContact",
    "proofOfPossession": "ProofOfPossession",
}


class ChallengeFactoryTest(unittest.TestCase):
    # pylint: disable=protected-access

    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler

        # Account is mocked...
        self.handler = AuthHandler(
            None, None, None, mock.Mock(key="mock_key"))

        self.dom = "test"
        self.handler.authzr[self.dom] = acme_util.gen_authzr(
            "pending", self.dom, acme_util.CHALLENGES, ["pending"]*6, False)

    def test_all(self):
        cont_c, dv_c = self.handler._challenge_factory(self.dom, range(0, 6))

        self.assertEqual(
            [achall.chall for achall in cont_c], acme_util.CONT_CHALLENGES)
        self.assertEqual(
            [achall.chall for achall in dv_c], acme_util.DV_CHALLENGES)

    def test_one_dv_one_cont(self):
        cont_c, dv_c = self.handler._challenge_factory(self.dom, [1, 4])

        self.assertEqual(
            [achall.chall for achall in cont_c], [acme_util.RECOVERY_TOKEN])
        self.assertEqual([achall.chall for achall in dv_c], [acme_util.DVSNI])

    def test_unrecognized(self):
        self.handler.authzr["failure.com"] = acme_util.gen_authzr(
            "pending", "failure.com",
            [mock.Mock(chall="chall", typ="unrecognized")], ["pending"])

        self.assertRaises(errors.LetsEncryptClientError,
                          self.handler._challenge_factory, "failure.com", [0])


class GetAuthorizationsTest(unittest.TestCase):
    """get_authorizations test.

    This tests everything except for all functions under _poll_challenges.

    """

    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler

        self.mock_dv_auth = mock.MagicMock(name="ApacheConfigurator")
        self.mock_cont_auth = mock.MagicMock(name="ContinuityAuthenticator")

        self.mock_dv_auth.get_chall_pref.return_value = [challenges.DVSNI]
        self.mock_cont_auth.get_chall_pref.return_value = [
            challenges.RecoveryToken]

        self.mock_cont_auth.perform.side_effect = gen_auth_resp
        self.mock_dv_auth.perform.side_effect = gen_auth_resp

        self.mock_account = mock.Mock(key=le_util.Key("file_path", "PEM"))
        self.mock_net = mock.MagicMock(spec=network2.Network)

        self.handler = AuthHandler(
            self.mock_dv_auth, self.mock_cont_auth,
            self.mock_net, self.mock_account)

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @mock.patch("letsencrypt.client.auth_handler.AuthHandler._poll_challenges")
    def test_name1_dvsni1(self, mock_poll):
        self.mock_net.request_domain_challenges.side_effect = functools.partial(
            gen_dom_authzr, challs=acme_util.DV_CHALLENGES)

        mock_poll.side_effect = self._validate_all

        authzr = self.handler.get_authorizations(["0"])

        self.assertEqual(self.mock_net.answer_challenge.call_count, 1)

        self.assertEqual(mock_poll.call_count, 1)
        chall_update = mock_poll.call_args[0][0]
        self.assertEqual(chall_update.keys(), ["0"])
        self.assertEqual(len(chall_update.values()), 1)

        self.assertEqual(self.mock_dv_auth.cleanup.call_count, 1)
        self.assertEqual(self.mock_cont_auth.cleanup.call_count, 0)
        # Test if list first element is DVSNI, use typ because it is an achall
        self.assertEqual(
            self.mock_dv_auth.cleanup.call_args[0][0][0].typ, "dvsni")

        self.assertEqual(len(authzr), 1)

    @mock.patch("letsencrypt.client.auth_handler.AuthHandler._poll_challenges")
    def test_name3_dvsni3_rectok_3(self, mock_poll):
        self.mock_net.request_domain_challenges.side_effect = functools.partial(
            gen_dom_authzr, challs=acme_util.CHALLENGES)

        mock_poll.side_effect = self._validate_all

        authzr = self.handler.get_authorizations(["0", "1", "2"])

        self.assertEqual(self.mock_net.answer_challenge.call_count, 6)

        # Check poll call
        self.assertEqual(mock_poll.call_count, 1)
        chall_update = mock_poll.call_args[0][0]
        self.assertEqual(len(chall_update.keys()), 3)
        self.assertTrue("0" in chall_update.keys())
        self.assertEqual(len(chall_update["0"]), 2)
        self.assertTrue("1" in chall_update.keys())
        self.assertEqual(len(chall_update["1"]), 2)
        self.assertTrue("2" in chall_update.keys())
        self.assertEqual(len(chall_update["2"]), 2)

        self.assertEqual(self.mock_dv_auth.cleanup.call_count, 1)
        self.assertEqual(self.mock_cont_auth.cleanup.call_count, 1)

        self.assertEqual(len(authzr), 3)

    def _get_exp_response(self, domain, path, challs):
        # pylint: disable=no-self-use
        exp_resp = [None] * len(challs)
        for i in path:
            exp_resp[i] = TRANSLATE[challs[i].typ] + str(domain)

        return exp_resp

    def _validate_all(self, unused_1, unused_2):
        for dom in self.handler.authzr.keys():
            azr = self.handler.authzr[dom]
            self.handler.authzr[dom] = acme_util.gen_authzr(
                "valid", dom, [challb.chall for challb in azr.body.challenges],
                ["valid"]*len(azr.body.challenges), azr.body.combinations)


class PollChallengesTest(unittest.TestCase):
    """Test poll challenges."""

    def setUp(self):
        from letsencrypt.client.auth_handler import AuthHandler
        # Account is mocked...
        self.handler = AuthHandler(
            None, None, None, mock.Mock(key="mock_key"))

        self.doms = ["0", "1", "2"]
        self.handler.authzr[self.doms[0]] = acme_util.gen_authzr(
            "pending", self.doms[0], acme_util.CHALLENGES, ["pending"]*6, False)

        self.handler.authzr[self.doms[1]] = acme_util.gen_authzr(
            "pending", self.doms[1], acme_util.CHALLENGES, ["pending"]*6, False)

        self.handler.authzr[self.doms[2]] = acme_util.gen_authzr(
            "pending", self.doms[2], acme_util.CHALLENGES, ["pending"]*6, False)

class GenChallengePathTest(unittest.TestCase):
    """Tests for letsencrypt.client.auth_handler.gen_challenge_path.

    .. todo:: Add more tests for dumb_path... depending on what we want to do.

    """
    def setUp(self):
        logging.disable(logging.fatal)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @classmethod
    def _call(cls, challbs, preferences, combinations):
        from letsencrypt.client.auth_handler import gen_challenge_path
        return gen_challenge_path(challbs, preferences, combinations)

    def test_common_case(self):
        """Given DVSNI and SimpleHTTPS with appropriate combos."""
        challbs = (acme_util.DVSNI_P, acme_util.SIMPLE_HTTPS_P)
        prefs = [challenges.DVSNI]
        combos = ((0,), (1,))

        # Smart then trivial dumb path test
        self.assertEqual(self._call(challbs, prefs, combos), (0,))
        self.assertTrue(self._call(challbs, prefs, None))
        # Rearrange order...
        self.assertEqual(self._call(challbs[::-1], prefs, combos), (1,))
        self.assertTrue(self._call(challbs[::-1], prefs, None))

    def test_common_case_with_continuity(self):
        challbs = (acme_util.RECOVERY_TOKEN_P,
                   acme_util.RECOVERY_CONTACT_P,
                   acme_util.DVSNI_P,
                   acme_util.SIMPLE_HTTPS_P)
        prefs = [challenges.RecoveryToken, challenges.DVSNI]
        combos = acme_util.gen_combos(challbs)
        self.assertEqual(self._call(challbs, prefs, combos), (0, 2))

         # dumb_path() trivial test
        self.assertTrue(self._call(challbs, prefs, None))

    def test_full_cont_server(self):
        challbs = (acme_util.RECOVERY_TOKEN_P,
                   acme_util.RECOVERY_CONTACT_P,
                   acme_util.POP_P,
                   acme_util.DVSNI_P,
                   acme_util.SIMPLE_HTTPS_P,
                   acme_util.DNS_P)
        # Typical webserver client that can do everything except DNS
        # Attempted to make the order realistic
        prefs = [challenges.RecoveryToken,
                 challenges.ProofOfPossession,
                 challenges.SimpleHTTPS,
                 challenges.DVSNI,
                 challenges.RecoveryContact]
        combos = acme_util.gen_combos(challbs)
        self.assertEqual(self._call(challbs, prefs, combos), (0, 4))

        # Dumb path trivial test
        self.assertTrue(self._call(challbs, prefs, None))

    def test_not_supported(self):
        challbs = (acme_util.POP_P, acme_util.DVSNI_P)
        prefs = [challenges.DVSNI]
        combos = ((0, 1),)

        self.assertRaises(errors.AuthorizationError,
                          self._call, challbs, prefs, combos)


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
        self.assertTrue(self._call(acme_util.DNS_P, frozenset()))

    def test_mutually_exclusvie(self):
        self.assertFalse(
            self._call(
                acme_util.DVSNI_P, frozenset([acme_util.SIMPLE_HTTPS_P])))

    def test_mutually_exclusive_same_type(self):
        self.assertTrue(
            self._call(acme_util.DVSNI_P, frozenset([acme_util.DVSNI_P])))


def gen_auth_resp(chall_list):
    """Generate a dummy authorization response."""
    return ["%s%s" % (chall.__class__.__name__, chall.domain)
            for chall in chall_list]


def gen_dom_authzr(domain, unused_new_authzr_uri, challs):
    """Generates new authzr for domains."""
    return acme_util.gen_authzr(
        "pending", domain, challs, ["pending"]*len(challs))


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
