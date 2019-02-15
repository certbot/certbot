"""Tests for certbot.auth_handler."""
import functools
import logging
import unittest

import mock
import zope.component

from acme import challenges
from acme import client as acme_client
from acme import messages

from certbot import achallenges
from certbot import errors
from certbot import interfaces
from certbot import util

from certbot.tests import acme_util
from certbot.tests import util as test_util


class ChallengeFactoryTest(unittest.TestCase):
    # pylint: disable=protected-access

    def setUp(self):
        from certbot.auth_handler import AuthHandler

        # Account is mocked...
        self.handler = AuthHandler(None, None, mock.Mock(key="mock_key"), [])

        self.authzr = acme_util.gen_authzr(
            messages.STATUS_PENDING, "test", acme_util.CHALLENGES,
            [messages.STATUS_PENDING] * 6, False)

    def test_all(self):
        achalls = self.handler._challenge_factory(
            self.authzr, range(0, len(acme_util.CHALLENGES)))

        self.assertEqual(
            [achall.chall for achall in achalls], acme_util.CHALLENGES)

    def test_one_tls_sni(self):
        achalls = self.handler._challenge_factory(self.authzr, [1])

        self.assertEqual(
            [achall.chall for achall in achalls], [acme_util.TLSSNI01])

    def test_unrecognized(self):
        authzr = acme_util.gen_authzr(
             messages.STATUS_PENDING, "test",
             [mock.Mock(chall="chall", typ="unrecognized")],
             [messages.STATUS_PENDING])

        self.assertRaises(
             errors.Error, self.handler._challenge_factory, authzr, [0])


class HandleAuthorizationsTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """handle_authorizations test.

    This tests everything except for all functions under _poll_challenges.

    """

    def setUp(self):
        from certbot.auth_handler import AuthHandler

        self.mock_display = mock.Mock()
        zope.component.provideUtility(
            self.mock_display, interfaces.IDisplay)
        zope.component.provideUtility(
            mock.Mock(debug_challenges=False), interfaces.IConfig)

        self.mock_auth = mock.MagicMock(name="ApacheConfigurator")

        self.mock_auth.get_chall_pref.return_value = [challenges.TLSSNI01]

        self.mock_auth.perform.side_effect = gen_auth_resp

        self.mock_account = mock.Mock(key=util.Key("file_path", "PEM"))
        self.mock_net = mock.MagicMock(spec=acme_client.Client)
        self.mock_net.acme_version = 1
        self.mock_net.retry_after.side_effect = acme_client.Client.retry_after

        self.handler = AuthHandler(
            self.mock_auth, self.mock_net, self.mock_account, [])

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def _test_name1_tls_sni_01_1_common(self, combos):
        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=combos)
        mock_order = mock.MagicMock(authorizations=[authzr])

        self.mock_net.poll.side_effect = _gen_mock_on_poll(retry=1)
        with mock.patch('certbot.auth_handler.time') as mock_time:
            authzr = self.handler.handle_authorizations(mock_order)

            self.assertEqual(self.mock_net.answer_challenge.call_count, 1)

            self.assertEqual(self.mock_net.poll.call_count, 2)  # Because there is one retry
            self.assertEqual(mock_time.sleep.call_count, 1)
            # Retry-After header is 1 second, but at the time sleep is invoked, several
            # instructions are executed, and next pool is in less than a second.
            self.assertTrue(mock_time.sleep.call_args[0][0] <= 1)

            self.assertEqual(self.mock_auth.cleanup.call_count, 1)
            # Test if list first element is TLSSNI01, use typ because it is an achall
            self.assertEqual(
                self.mock_auth.cleanup.call_args[0][0][0].typ, "tls-sni-01")

            self.assertEqual(len(authzr), 1)

    def test_name1_tls_sni_01_1_acme_1(self):
        self._test_name1_tls_sni_01_1_common(combos=True)

    def test_name1_tls_sni_01_1_acme_2(self):
        self.mock_net.acme_version = 2
        self._test_name1_tls_sni_01_1_common(combos=False)

    def test_name1_tls_sni_01_1_http_01_1_dns_1_acme_1(self):
        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        self.mock_auth.get_chall_pref.return_value.append(challenges.HTTP01)
        self.mock_auth.get_chall_pref.return_value.append(challenges.DNS01)

        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        authzr = self.handler.handle_authorizations(mock_order)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 3)

        self.assertEqual(self.mock_net.poll.call_count, 1)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        # Test if list first element is TLSSNI01, use typ because it is an achall
        for achall in self.mock_auth.cleanup.call_args[0][0]:
            self.assertTrue(achall.typ in ["tls-sni-01", "http-01", "dns-01"])

        # Length of authorizations list
        self.assertEqual(len(authzr), 1)

    def test_name1_tls_sni_01_1_http_01_1_dns_1_acme_2(self):
        self.mock_net.acme_version = 2
        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        self.mock_auth.get_chall_pref.return_value.append(challenges.HTTP01)
        self.mock_auth.get_chall_pref.return_value.append(challenges.DNS01)

        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        authzr = self.handler.handle_authorizations(mock_order)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 1)

        self.assertEqual(self.mock_net.poll.call_count, 1)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        cleaned_up_achalls = self.mock_auth.cleanup.call_args[0][0]
        self.assertEqual(len(cleaned_up_achalls), 1)
        self.assertEqual(cleaned_up_achalls[0].typ, "tls-sni-01")

        # Length of authorizations list
        self.assertEqual(len(authzr), 1)

    def _test_name3_tls_sni_01_3_common(self, combos):
        self.mock_net.request_domain_challenges.side_effect = functools.partial(
            gen_dom_authzr, challs=acme_util.CHALLENGES, combos=combos)

        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES),
                   gen_dom_authzr(domain="1", challs=acme_util.CHALLENGES),
                   gen_dom_authzr(domain="2", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        authzr = self.handler.handle_authorizations(mock_order)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 3)

        # Check poll call
        self.assertEqual(self.mock_net.poll.call_count, 3)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)

        self.assertEqual(len(authzr), 3)

    def test_name3_tls_sni_01_3_common_acme_1(self):
        self._test_name3_tls_sni_01_3_common(combos=True)

    def test_name3_tls_sni_01_3_common_acme_2(self):
        self.mock_net.acme_version = 2
        self._test_name3_tls_sni_01_3_common(combos=False)

    def test_debug_challenges(self):
        zope.component.provideUtility(
            mock.Mock(debug_challenges=True), interfaces.IConfig)
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_net.poll.side_effect = _gen_mock_on_poll()

        self.handler.handle_authorizations(mock_order)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 1)
        self.assertEqual(self.mock_display.notification.call_count, 1)

    def test_perform_failure(self):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_auth.perform.side_effect = errors.AuthorizationError

        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations, mock_order)

    def test_max_retries_exceeded(self):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        # We will return STATUS_PENDING twice before returning STATUS_VALID.
        self.mock_net.poll.side_effect = _gen_mock_on_poll(retry=2)

        with self.assertRaises(errors.AuthorizationError) as error:
            # We retry only once, so retries will be exhausted before STATUS_VALID is returned.
            self.handler.handle_authorizations(mock_order, False, 1)
        self.assertTrue('All challenges could not be checked on time' in str(error.exception))

        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations, mock_order, False, 1)

    def test_no_domains(self):
        mock_order = mock.MagicMock(authorizations=[])
        self.assertRaises(errors.AuthorizationError, self.handler.handle_authorizations, mock_order)

    def _test_preferred_challenge_choice_common(self, combos):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=combos)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_auth.get_chall_pref.return_value.append(challenges.HTTP01)

        self.handler.pref_challs.extend((challenges.HTTP01.typ,
                                         challenges.DNS01.typ,))

        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        self.handler.handle_authorizations(mock_order)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        self.assertEqual(
            self.mock_auth.cleanup.call_args[0][0][0].typ, "http-01")

    def test_preferred_challenge_choice_common_acme_1(self):
        self._test_preferred_challenge_choice_common(combos=True)

    def test_preferred_challenge_choice_common_acme_2(self):
        self.mock_net.acme_version = 2
        self._test_preferred_challenge_choice_common(combos=False)

    def _test_preferred_challenges_not_supported_common(self, combos):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=combos)]
        mock_order = mock.MagicMock(authorizations=authzrs)
        self.handler.pref_challs.append(challenges.HTTP01.typ)
        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations, mock_order)

    def test_preferred_challenges_not_supported_acme_1(self):
        self._test_preferred_challenges_not_supported_common(combos=True)

    def test_preferred_challenges_not_supported_acme_2(self):
        self.mock_net.acme_version = 2
        self._test_preferred_challenges_not_supported_common(combos=False)

    def test_dns_only_challenge_not_supported(self):
        authzrs = [gen_dom_authzr(domain="0", challs=[acme_util.DNS01])]
        mock_order = mock.MagicMock(authorizations=authzrs)
        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations, mock_order)

    def test_perform_error(self):
        self.mock_auth.perform.side_effect = errors.AuthorizationError

        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=True)
        mock_order = mock.MagicMock(authorizations=[authzr])
        self.assertRaises(errors.AuthorizationError, self.handler.handle_authorizations, mock_order)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        self.assertEqual(
            self.mock_auth.cleanup.call_args[0][0][0].typ, "tls-sni-01")

    def test_answer_error(self):
        self.mock_net.answer_challenge.side_effect = errors.AuthorizationError

        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations, mock_order)
        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        self.assertEqual(
            self.mock_auth.cleanup.call_args[0][0][0].typ, "tls-sni-01")

    def test_incomplete_authzr_error(self):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)
        self.mock_net.poll.side_effect = _gen_mock_on_poll(status=messages.STATUS_INVALID)

        with self.assertRaises(errors.AuthorizationError) as error:
            self.handler.handle_authorizations(mock_order, False)
        self.assertTrue('Some challenges have failed' in str(error.exception))
        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        self.assertEqual(
            self.mock_auth.cleanup.call_args[0][0][0].typ, "tls-sni-01")

    def test_best_effort(self):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)
        self.mock_net.poll.side_effect = _gen_mock_on_poll(status=messages.STATUS_INVALID)

        # Expect to fail with best_effort, because all authorizations will fail,
        # but not on a individual poll, instead logger.warning have been called.
        with mock.patch('certbot.auth_handler.logger') as mock_logger:
            with self.assertRaises(errors.AuthorizationError) as error:
                self.handler.handle_authorizations(mock_order, True)
        self.assertTrue(mock_logger.warning.call_count > 1)
        self.assertTrue('Following authorizations have failed'
                        in mock_logger.warning.call_args[0][0])
        self.assertTrue('All challenges have failed' in str(error.exception))

    def test_validated_challenge_not_rerun(self):
        # With pending challenge, we expect the challenge to be tried, and fail.
        authzr = acme_util.gen_authzr(
                messages.STATUS_PENDING, "0",
                [acme_util.HTTP01],
                [messages.STATUS_PENDING], False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations, mock_order)

        # With validated challenge; we expect the challenge not be tried again, and succeed.
        authzr = acme_util.gen_authzr(
                messages.STATUS_VALID, "0",
                [acme_util.HTTP01],
                [messages.STATUS_VALID], False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        self.handler.handle_authorizations(mock_order)

    @mock.patch("certbot.auth_handler.logger")
    def test_tls_sni_logs(self, logger):
        self._test_name1_tls_sni_01_1_common(combos=True)
        self.assertTrue("deprecated" in logger.warning.call_args[0][0])


def _gen_mock_on_poll(status=messages.STATUS_VALID, retry=0):
    state = {'count': retry}

    def _mock(authzr):
        state['count'] = state['count'] - 1
        effective_status = status if state['count'] < 0 else messages.STATUS_PENDING
        updated_azr = acme_util.gen_authzr(
            effective_status,
            authzr.body.identifier.value,
            [challb.chall for challb in authzr.body.challenges],
            [effective_status] * len(authzr.body.challenges),
            authzr.body.combinations)
        return updated_azr, mock.MagicMock(headers={'Retry-After': '1'})
    return _mock


class ChallbToAchallTest(unittest.TestCase):
    """Tests for certbot.auth_handler.challb_to_achall."""

    def _call(self, challb):
        from certbot.auth_handler import challb_to_achall
        return challb_to_achall(challb, "account_key", "domain")

    def test_it(self):
        self.assertEqual(
            self._call(acme_util.HTTP01_P),
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.HTTP01_P, account_key="account_key",
                domain="domain"),
        )


class GenChallengePathTest(unittest.TestCase):
    """Tests for certbot.auth_handler.gen_challenge_path.

    .. todo:: Add more tests for dumb_path... depending on what we want to do.

    """
    def setUp(self):
        logging.disable(logging.FATAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @classmethod
    def _call(cls, challbs, preferences, combinations):
        from certbot.auth_handler import gen_challenge_path
        return gen_challenge_path(challbs, preferences, combinations)

    def test_common_case(self):
        """Given TLSSNI01 and HTTP01 with appropriate combos."""
        challbs = (acme_util.TLSSNI01_P, acme_util.HTTP01_P)
        prefs = [challenges.TLSSNI01, challenges.HTTP01]
        combos = ((0,), (1,))

        # Smart then trivial dumb path test
        self.assertEqual(self._call(challbs, prefs, combos), (0,))
        self.assertTrue(self._call(challbs, prefs, None))
        # Rearrange order...
        self.assertEqual(self._call(challbs[::-1], prefs, combos), (1,))
        self.assertTrue(self._call(challbs[::-1], prefs, None))

    def test_not_supported(self):
        challbs = (acme_util.DNS01_P, acme_util.TLSSNI01_P)
        prefs = [challenges.TLSSNI01]
        combos = ((0, 1),)

        # smart path fails because no challs in perfs satisfies combos
        self.assertRaises(
            errors.AuthorizationError, self._call, challbs, prefs, combos)
        # dumb path fails because all challbs are not supported
        self.assertRaises(
            errors.AuthorizationError, self._call, challbs, prefs, None)


class ReportFailedChallsTest(unittest.TestCase):
    """Tests for certbot.auth_handler._report_failed_challs."""
    # pylint: disable=protected-access

    def setUp(self):
        kwargs = {
            "chall": acme_util.HTTP01,
            "uri": "uri",
            "status": messages.STATUS_INVALID,
            "error": messages.Error.with_code("tls", detail="detail"),
        }

        # Prevent future regressions if the error type changes
        self.assertTrue(kwargs["error"].description is not None)

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

    @test_util.patch_get_utility()
    def test_same_error_and_domain(self, mock_zope):
        from certbot import auth_handler

        auth_handler._report_failed_challs([self.http01, self.tls_sni_same])
        call_list = mock_zope().add_message.call_args_list
        self.assertTrue(len(call_list) == 1)
        self.assertTrue("Domain: example.com\nType:   tls\nDetail: detail" in call_list[0][0][0])

    @test_util.patch_get_utility()
    def test_different_errors_and_domains(self, mock_zope):
        from certbot import auth_handler

        auth_handler._report_failed_challs([self.http01, self.tls_sni_diff])
        self.assertTrue(mock_zope().add_message.call_count == 2)


def gen_auth_resp(chall_list):
    """Generate a dummy authorization response."""
    return ["%s%s" % (chall.__class__.__name__, chall.domain)
            for chall in chall_list]


def gen_dom_authzr(domain, challs, combos=True):
    """Generates new authzr for domains."""
    return acme_util.gen_authzr(
        messages.STATUS_PENDING, domain, challs,
        [messages.STATUS_PENDING] * len(challs), combos)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
