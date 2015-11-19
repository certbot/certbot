"""Tests for letsencrypt.auth_handler."""
import functools
import logging
import unittest

import mock

from acme import challenges
from acme import client as acme_client
from acme import messages

from letsencrypt import achallenges
from letsencrypt import errors
from letsencrypt import le_util

from letsencrypt.tests import acme_util


class ChallengeFactoryTest(unittest.TestCase):
    # pylint: disable=protected-access

    def setUp(self):
        from letsencrypt.auth_handler import AuthHandler

        # Account is mocked...
        self.handler = AuthHandler(
            None, None, None, mock.Mock(key="mock_key"))

        self.dom = "test"
        self.handler.authzr[self.dom] = acme_util.gen_authzr(
            messages.STATUS_PENDING, self.dom, acme_util.CHALLENGES,
            [messages.STATUS_PENDING] * 6, False)

    def test_all(self):
        cont_c, dv_c = self.handler._challenge_factory(
            self.dom, range(0, len(acme_util.CHALLENGES)))

        self.assertEqual(
            [achall.chall for achall in cont_c], acme_util.CONT_CHALLENGES)
        self.assertEqual(
            [achall.chall for achall in dv_c], acme_util.DV_CHALLENGES)

    def test_one_dv_one_cont(self):
        cont_c, dv_c = self.handler._challenge_factory(self.dom, [1, 3])

        self.assertEqual(
            [achall.chall for achall in cont_c], [acme_util.RECOVERY_CONTACT])
        self.assertEqual([achall.chall for achall in dv_c], [acme_util.TLSSNI01])

    def test_unrecognized(self):
        self.handler.authzr["failure.com"] = acme_util.gen_authzr(
            messages.STATUS_PENDING, "failure.com",
            [mock.Mock(chall="chall", typ="unrecognized")],
            [messages.STATUS_PENDING])

        self.assertRaises(
            errors.Error, self.handler._challenge_factory, "failure.com", [0])


class GetAuthorizationsTest(unittest.TestCase):
    """get_authorizations test.

    This tests everything except for all functions under _poll_challenges.

    """

    def setUp(self):
        from letsencrypt.auth_handler import AuthHandler

        self.mock_dv_auth = mock.MagicMock(name="ApacheConfigurator")
        self.mock_cont_auth = mock.MagicMock(name="ContinuityAuthenticator")

        self.mock_dv_auth.get_chall_pref.return_value = [challenges.TLSSNI01]
        self.mock_cont_auth.get_chall_pref.return_value = [
            challenges.RecoveryContact]

        self.mock_cont_auth.perform.side_effect = gen_auth_resp
        self.mock_dv_auth.perform.side_effect = gen_auth_resp

        self.mock_account = mock.Mock(key=le_util.Key("file_path", "PEM"))
        self.mock_net = mock.MagicMock(spec=acme_client.Client)

        self.handler = AuthHandler(
            self.mock_dv_auth, self.mock_cont_auth,
            self.mock_net, self.mock_account)

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @mock.patch("letsencrypt.auth_handler.AuthHandler._poll_challenges")
    def test_name1_tls_sni_01_1(self, mock_poll):
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
        # Test if list first element is TLSSNI01, use typ because it is an achall
        self.assertEqual(
            self.mock_dv_auth.cleanup.call_args[0][0][0].typ, "tls-sni-01")

        self.assertEqual(len(authzr), 1)

    @mock.patch("letsencrypt.auth_handler.AuthHandler._poll_challenges")
    def test_name3_tls_sni_01_3_rectok_3(self, mock_poll):
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

    def test_perform_failure(self):
        self.mock_net.request_domain_challenges.side_effect = functools.partial(
            gen_dom_authzr, challs=acme_util.CHALLENGES)
        self.mock_dv_auth.perform.side_effect = errors.AuthorizationError

        self.assertRaises(
            errors.AuthorizationError, self.handler.get_authorizations, ["0"])

    def _validate_all(self, unused_1, unused_2):
        for dom in self.handler.authzr.keys():
            azr = self.handler.authzr[dom]
            self.handler.authzr[dom] = acme_util.gen_authzr(
                messages.STATUS_VALID,
                dom,
                [challb.chall for challb in azr.body.challenges],
                [messages.STATUS_VALID] * len(azr.body.challenges),
                azr.body.combinations)


class PollChallengesTest(unittest.TestCase):
    # pylint: disable=protected-access
    """Test poll challenges."""

    def setUp(self):
        from letsencrypt.auth_handler import challb_to_achall
        from letsencrypt.auth_handler import AuthHandler

        # Account and network are mocked...
        self.mock_net = mock.MagicMock()
        self.handler = AuthHandler(
            None, None, self.mock_net, mock.Mock(key="mock_key"))

        self.doms = ["0", "1", "2"]
        self.handler.authzr[self.doms[0]] = acme_util.gen_authzr(
            messages.STATUS_PENDING, self.doms[0],
            acme_util.DV_CHALLENGES, [messages.STATUS_PENDING] * 3, False)

        self.handler.authzr[self.doms[1]] = acme_util.gen_authzr(
            messages.STATUS_PENDING, self.doms[1],
            acme_util.DV_CHALLENGES, [messages.STATUS_PENDING] * 3, False)

        self.handler.authzr[self.doms[2]] = acme_util.gen_authzr(
            messages.STATUS_PENDING, self.doms[2],
            acme_util.DV_CHALLENGES, [messages.STATUS_PENDING] * 3, False)

        self.chall_update = {}
        for dom in self.doms:
            self.chall_update[dom] = [
                challb_to_achall(challb, mock.Mock(key="dummy_key"), dom)
                for challb in self.handler.authzr[dom].body.challenges]

    @mock.patch("letsencrypt.auth_handler.time")
    def test_poll_challenges(self, unused_mock_time):
        self.mock_net.poll.side_effect = self._mock_poll_solve_one_valid
        self.handler._poll_challenges(self.chall_update, False)

        for authzr in self.handler.authzr.values():
            self.assertEqual(authzr.body.status, messages.STATUS_VALID)

    @mock.patch("letsencrypt.auth_handler.time")
    def test_poll_challenges_failure_best_effort(self, unused_mock_time):
        self.mock_net.poll.side_effect = self._mock_poll_solve_one_invalid
        self.handler._poll_challenges(self.chall_update, True)

        for authzr in self.handler.authzr.values():
            self.assertEqual(authzr.body.status, messages.STATUS_PENDING)

    @mock.patch("letsencrypt.auth_handler.time")
    @mock.patch("letsencrypt.auth_handler.zope.component.getUtility")
    def test_poll_challenges_failure(self, unused_mock_time, unused_mock_zope):
        self.mock_net.poll.side_effect = self._mock_poll_solve_one_invalid
        self.assertRaises(
            errors.AuthorizationError, self.handler._poll_challenges,
            self.chall_update, False)

    @mock.patch("letsencrypt.auth_handler.time")
    def test_unable_to_find_challenge_status(self, unused_mock_time):
        from letsencrypt.auth_handler import challb_to_achall
        self.mock_net.poll.side_effect = self._mock_poll_solve_one_valid
        self.chall_update[self.doms[0]].append(
            challb_to_achall(acme_util.RECOVERY_CONTACT_P, "key", self.doms[0]))
        self.assertRaises(
            errors.AuthorizationError, self.handler._poll_challenges,
            self.chall_update, False)

    def test_verify_authzr_failure(self):
        self.assertRaises(
            errors.AuthorizationError, self.handler.verify_authzr_complete)

    def _mock_poll_solve_one_valid(self, authzr):
        # Pending here because my dummy script won't change the full status.
        # Basically it didn't raise an error and it stopped earlier than
        # Making all challenges invalid which would make mock_poll_solve_one
        # change authzr to invalid
        return self._mock_poll_solve_one_chall(authzr, messages.STATUS_VALID)

    def _mock_poll_solve_one_invalid(self, authzr):
        return self._mock_poll_solve_one_chall(authzr, messages.STATUS_INVALID)

    def _mock_poll_solve_one_chall(self, authzr, desired_status):
        # pylint: disable=no-self-use
        """Dummy method that solves one chall at a time to desired_status.

        When all are solved.. it changes authzr.status to desired_status

        """
        new_challbs = authzr.body.challenges
        for challb in authzr.body.challenges:
            if challb.status != desired_status:
                new_challbs = tuple(
                    challb_temp if challb_temp != challb
                    else acme_util.chall_to_challb(challb.chall, desired_status)
                    for challb_temp in authzr.body.challenges
                )
                break

        if all(test_challb.status == desired_status
               for test_challb in new_challbs):
            status_ = desired_status
        else:
            status_ = authzr.body.status

        new_authzr = messages.AuthorizationResource(
            uri=authzr.uri,
            new_cert_uri=authzr.new_cert_uri,
            body=messages.Authorization(
                identifier=authzr.body.identifier,
                challenges=new_challbs,
                combinations=authzr.body.combinations,
                status=status_,
            ),
        )
        return (new_authzr, "response")


class ChallbToAchallTest(unittest.TestCase):
    """Tests for letsencrypt.auth_handler.challb_to_achall."""

    def _call(self, challb):
        from letsencrypt.auth_handler import challb_to_achall
        return challb_to_achall(challb, "account_key", "domain")

    def test_it(self):
        self.assertEqual(
            self._call(acme_util.HTTP01_P),
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.HTTP01_P, account_key="account_key",
                domain="domain"),
        )


class GenChallengePathTest(unittest.TestCase):
    """Tests for letsencrypt.auth_handler.gen_challenge_path.

    .. todo:: Add more tests for dumb_path... depending on what we want to do.

    """
    def setUp(self):
        logging.disable(logging.fatal)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @classmethod
    def _call(cls, challbs, preferences, combinations):
        from letsencrypt.auth_handler import gen_challenge_path
        return gen_challenge_path(challbs, preferences, combinations)

    def test_common_case(self):
        """Given TLSSNI01 and HTTP01 with appropriate combos."""
        challbs = (acme_util.TLSSNI01_P, acme_util.HTTP01_P)
        prefs = [challenges.TLSSNI01]
        combos = ((0,), (1,))

        # Smart then trivial dumb path test
        self.assertEqual(self._call(challbs, prefs, combos), (0,))
        self.assertTrue(self._call(challbs, prefs, None))
        # Rearrange order...
        self.assertEqual(self._call(challbs[::-1], prefs, combos), (1,))
        self.assertTrue(self._call(challbs[::-1], prefs, None))

    def test_common_case_with_continuity(self):
        challbs = (acme_util.POP_P,
                   acme_util.RECOVERY_CONTACT_P,
                   acme_util.TLSSNI01_P,
                   acme_util.HTTP01_P)
        prefs = [challenges.ProofOfPossession, challenges.TLSSNI01]
        combos = acme_util.gen_combos(challbs)
        self.assertEqual(self._call(challbs, prefs, combos), (0, 2))

        # dumb_path() trivial test
        self.assertTrue(self._call(challbs, prefs, None))

    def test_full_cont_server(self):
        challbs = (acme_util.RECOVERY_CONTACT_P,
                   acme_util.POP_P,
                   acme_util.TLSSNI01_P,
                   acme_util.HTTP01_P,
                   acme_util.DNS_P)
        # Typical webserver client that can do everything except DNS
        # Attempted to make the order realistic
        prefs = [challenges.ProofOfPossession,
                 challenges.HTTP01,
                 challenges.TLSSNI01,
                 challenges.RecoveryContact]
        combos = acme_util.gen_combos(challbs)
        self.assertEqual(self._call(challbs, prefs, combos), (1, 3))

        # Dumb path trivial test
        self.assertTrue(self._call(challbs, prefs, None))

    def test_not_supported(self):
        challbs = (acme_util.POP_P, acme_util.TLSSNI01_P)
        prefs = [challenges.TLSSNI01]
        combos = ((0, 1),)

        self.assertRaises(
            errors.AuthorizationError, self._call, challbs, prefs, combos)


class MutuallyExclusiveTest(unittest.TestCase):
    """Tests for letsencrypt.auth_handler.mutually_exclusive."""

    # pylint: disable=missing-docstring,too-few-public-methods
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
        from letsencrypt.auth_handler import mutually_exclusive
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
    """Tests for letsencrypt.auth_handler.is_preferred."""

    @classmethod
    def _call(cls, chall, satisfied):
        from letsencrypt.auth_handler import is_preferred
        return is_preferred(chall, satisfied, exclusive_groups=frozenset([
            frozenset([challenges.TLSSNI01, challenges.HTTP01]),
            frozenset([challenges.DNS, challenges.HTTP01]),
        ]))

    def test_empty_satisfied(self):
        self.assertTrue(self._call(acme_util.DNS_P, frozenset()))

    def test_mutually_exclusvie(self):
        self.assertFalse(
            self._call(
                acme_util.TLSSNI01_P, frozenset([acme_util.HTTP01_P])))

    def test_mutually_exclusive_same_type(self):
        self.assertTrue(
            self._call(acme_util.TLSSNI01_P, frozenset([acme_util.TLSSNI01_P])))


class ReportFailedChallsTest(unittest.TestCase):
    """Tests for letsencrypt.auth_handler._report_failed_challs."""
    # pylint: disable=protected-access

    def setUp(self):
        kwargs = {
            "chall": acme_util.HTTP01,
            "uri": "uri",
            "status": messages.STATUS_INVALID,
            "error": messages.Error(typ="tls", detail="detail"),
        }

        self.http01 = achallenges.KeyAuthorizationAnnotatedChallenge(
            # pylint: disable=star-args
            challb=messages.ChallengeBody(**kwargs),
            domain="example.com",
            account_key="key")

        kwargs["chall"] = acme_util.TLSSNI01
        self.tls_sni_same = achallenges.KeyAuthorizationAnnotatedChallenge(
            # pylint: disable=star-args
            challb=messages.ChallengeBody(**kwargs),
            domain="example.com",
            account_key="key")

        kwargs["error"] = messages.Error(typ="dnssec", detail="detail")
        self.tls_sni_diff = achallenges.KeyAuthorizationAnnotatedChallenge(
            # pylint: disable=star-args
            challb=messages.ChallengeBody(**kwargs),
            domain="foo.bar",
            account_key="key")

    @mock.patch("letsencrypt.auth_handler.zope.component.getUtility")
    def test_same_error_and_domain(self, mock_zope):
        from letsencrypt import auth_handler

        auth_handler._report_failed_challs([self.http01, self.tls_sni_same])
        call_list = mock_zope().add_message.call_args_list
        self.assertTrue(len(call_list) == 1)
        self.assertTrue("Domains: example.com\n" in call_list[0][0][0])

    @mock.patch("letsencrypt.auth_handler.zope.component.getUtility")
    def test_different_errors_and_domains(self, mock_zope):
        from letsencrypt import auth_handler

        auth_handler._report_failed_challs([self.http01, self.tls_sni_diff])
        self.assertTrue(mock_zope().add_message.call_count == 2)


def gen_auth_resp(chall_list):
    """Generate a dummy authorization response."""
    return ["%s%s" % (chall.__class__.__name__, chall.domain)
            for chall in chall_list]


def gen_dom_authzr(domain, unused_new_authzr_uri, challs):
    """Generates new authzr for domains."""
    return acme_util.gen_authzr(
        messages.STATUS_PENDING, domain, challs,
        [messages.STATUS_PENDING] * len(challs))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
