"""Tests for certbot._internal.auth_handler."""
import functools
import logging
import unittest

try:
    import mock
except ImportError:  # pragma: no cover
    from unittest import mock

from acme import challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import messages
from certbot import achallenges
from certbot import errors
from certbot import util
from certbot._internal.display import obj as display_obj
from certbot.plugins import common as plugin_common
from certbot.tests import acme_util
from certbot.tests import util as test_util


class ChallengeFactoryTest(unittest.TestCase):
    # pylint: disable=protected-access

    def setUp(self):
        from certbot._internal.auth_handler import AuthHandler

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

    def test_one_http(self):
        achalls = self.handler._challenge_factory(self.authzr, [0])

        self.assertEqual(
            [achall.chall for achall in achalls], [acme_util.HTTP01])

    def test_unrecognized(self):
        authzr = acme_util.gen_authzr(
             messages.STATUS_PENDING, "test",
             [mock.Mock(chall="chall", typ="unrecognized")],
             [messages.STATUS_PENDING])

        self.assertRaises(
             errors.Error, self.handler._challenge_factory, authzr, [0])


class HandleAuthorizationsTest(unittest.TestCase):
    """handle_authorizations test.

    This tests everything except for all functions under _poll_challenges.

    """

    def setUp(self):
        from certbot._internal.auth_handler import AuthHandler

        self.mock_display = mock.Mock()
        self.mock_config = mock.Mock(debug_challenges=False)
        with mock.patch("zope.component.provideUtility"):
            display_obj.set_display(self.mock_display)

        self.mock_auth = mock.MagicMock(name="ApacheConfigurator")

        self.mock_auth.get_chall_pref.return_value = [challenges.HTTP01]

        self.mock_auth.perform.side_effect = gen_auth_resp

        self.mock_account = mock.MagicMock()
        self.mock_net = mock.MagicMock(spec=acme_client.ClientV2)
        self.mock_net.acme_version = 1
        self.mock_net.retry_after.side_effect = acme_client.ClientV2.retry_after

        self.handler = AuthHandler(
            self.mock_auth, self.mock_net, self.mock_account, [])

        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def _test_name1_http_01_1_common(self, combos):
        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=combos)
        mock_order = mock.MagicMock(authorizations=[authzr])

        self.mock_net.poll.side_effect = _gen_mock_on_poll(retry=1, wait_value=30)
        with mock.patch('certbot._internal.auth_handler.time') as mock_time:
            authzr = self.handler.handle_authorizations(mock_order, self.mock_config)

            self.assertEqual(self.mock_net.answer_challenge.call_count, 1)

            self.assertEqual(self.mock_net.poll.call_count, 2)  # Because there is one retry
            self.assertEqual(mock_time.sleep.call_count, 2)
            # Retry-After header is 30 seconds, but at the time sleep is invoked, several
            # instructions are executed, and next pool is in less than 30 seconds.
            self.assertLessEqual(mock_time.sleep.call_args_list[1][0][0], 30)
            # However, assert that we did not took the default value of 3 seconds.
            self.assertGreater(mock_time.sleep.call_args_list[1][0][0], 3)

            self.assertEqual(self.mock_auth.cleanup.call_count, 1)
            # Test if list first element is http-01, use typ because it is an achall
            self.assertEqual(
                self.mock_auth.cleanup.call_args[0][0][0].typ, "http-01")

            self.assertEqual(len(authzr), 1)

    def test_name1_http_01_1_acme_1(self):
        self._test_name1_http_01_1_common(combos=True)

    def test_name1_http_01_1_acme_2(self):
        self.mock_net.acme_version = 2
        self._test_name1_http_01_1_common(combos=False)

    def test_name1_http_01_1_dns_1_acme_1(self):
        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        self.mock_auth.get_chall_pref.return_value.append(challenges.DNS01)

        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        authzr = self.handler.handle_authorizations(mock_order, self.mock_config)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 2)

        self.assertEqual(self.mock_net.poll.call_count, 1)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        # Test if list first element is http-01, use typ because it is an achall
        for achall in self.mock_auth.cleanup.call_args[0][0]:
            self.assertIn(achall.typ, ["http-01", "dns-01"])

        # Length of authorizations list
        self.assertEqual(len(authzr), 1)

    def test_name1_http_01_1_dns_1_acme_2(self):
        self.mock_net.acme_version = 2
        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        self.mock_auth.get_chall_pref.return_value.append(challenges.DNS01)

        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        authzr = self.handler.handle_authorizations(mock_order, self.mock_config)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 1)

        self.assertEqual(self.mock_net.poll.call_count, 1)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        cleaned_up_achalls = self.mock_auth.cleanup.call_args[0][0]
        self.assertEqual(len(cleaned_up_achalls), 1)
        self.assertEqual(cleaned_up_achalls[0].typ, "http-01")

        # Length of authorizations list
        self.assertEqual(len(authzr), 1)

    def _test_name3_http_01_3_common(self, combos):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES),
                   gen_dom_authzr(domain="1", challs=acme_util.CHALLENGES),
                   gen_dom_authzr(domain="2", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        authzr = self.handler.handle_authorizations(mock_order, self.mock_config)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 3)

        # Check poll call
        self.assertEqual(self.mock_net.poll.call_count, 3)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)

        self.assertEqual(len(authzr), 3)

    def test_name3_http_01_3_common_acme_1(self):
        self._test_name3_http_01_3_common(combos=True)

    def test_name3_http_01_3_common_acme_2(self):
        self.mock_net.acme_version = 2
        self._test_name3_http_01_3_common(combos=False)

    def test_debug_challenges(self):
        config = mock.Mock(debug_challenges=True)
        config.namespace.verbose_count = 0
        authzrs = [gen_dom_authzr(domain="0", challs=[acme_util.HTTP01])]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_net.poll.side_effect = _gen_mock_on_poll()

        self.handler.handle_authorizations(mock_order, config)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 1)
        self.assertEqual(self.mock_display.notification.call_count, 1)
        self.assertIn('Pass "-v" for more info',
                      self.mock_display.notification.call_args[0][0])
        self.assertNotIn(f"http://{authzrs[0].body.identifier.value}/.well-known/acme-challenge/",
                         self.mock_display.notification.call_args[0][0])

    def test_debug_challenges_verbose(self):
        config = mock.Mock(debug_challenges=True)
        config.namespace.verbose_count = 1
        authzrs = [gen_dom_authzr(domain="0", challs=[acme_util.HTTP01])]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_account.key.thumbprint.return_value = b"foo"

        self.mock_net.poll.side_effect = _gen_mock_on_poll()

        self.handler.handle_authorizations(mock_order, config)

        self.assertEqual(self.mock_net.answer_challenge.call_count, 1)
        self.assertEqual(self.mock_display.notification.call_count, 1)
        self.assertNotIn('Pass "-v" for more info',
                         self.mock_display.notification.call_args[0][0])
        self.assertIn(f"http://{authzrs[0].body.identifier.value}/.well-known/acme-challenge/",
                      self.mock_display.notification.call_args[0][0])

    def test_perform_failure(self):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_auth.perform.side_effect = errors.AuthorizationError

        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations,
            mock_order, self.mock_config)

    def test_max_retries_exceeded(self):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        # We will return STATUS_PENDING twice before returning STATUS_VALID.
        self.mock_net.poll.side_effect = _gen_mock_on_poll(retry=2)

        with self.assertRaises(errors.AuthorizationError) as error:
            # We retry only once, so retries will be exhausted before STATUS_VALID is returned.
            self.handler.handle_authorizations(mock_order, self.mock_config, False, 1)
        self.assertIn('All authorizations were not finalized by the CA.', str(error.exception))

    def test_no_domains(self):
        mock_order = mock.MagicMock(authorizations=[])
        self.assertRaises(errors.AuthorizationError, self.handler.handle_authorizations,
                          mock_order, self.mock_config)

    def _test_preferred_challenge_choice_common(self, combos):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=combos)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.mock_auth.get_chall_pref.return_value.append(challenges.HTTP01)

        self.handler.pref_challs.extend((challenges.HTTP01.typ,
                                         challenges.DNS01.typ,))

        self.mock_net.poll.side_effect = _gen_mock_on_poll()
        self.handler.handle_authorizations(mock_order, self.mock_config)

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
        self.handler.pref_challs.append(challenges.DNS01.typ)
        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations,
            mock_order, self.mock_config)

    def test_preferred_challenges_not_supported_acme_1(self):
        self._test_preferred_challenges_not_supported_common(combos=True)

    def test_preferred_challenges_not_supported_acme_2(self):
        self.mock_net.acme_version = 2
        self._test_preferred_challenges_not_supported_common(combos=False)

    def test_dns_only_challenge_not_supported(self):
        authzrs = [gen_dom_authzr(domain="0", challs=[acme_util.DNS01])]
        mock_order = mock.MagicMock(authorizations=authzrs)
        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations,
            mock_order, self.mock_config)

    def test_perform_error(self):
        self.mock_auth.perform.side_effect = errors.AuthorizationError

        authzr = gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES, combos=True)
        mock_order = mock.MagicMock(authorizations=[authzr])
        self.assertRaises(errors.AuthorizationError, self.handler.handle_authorizations,
                          mock_order, self.mock_config)

        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        self.assertEqual(
            self.mock_auth.cleanup.call_args[0][0][0].typ, "http-01")

    def test_answer_error(self):
        self.mock_net.answer_challenge.side_effect = errors.AuthorizationError

        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)

        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations,
            mock_order, self.mock_config)
        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        self.assertEqual(
            self.mock_auth.cleanup.call_args[0][0][0].typ, "http-01")

    def test_incomplete_authzr_error(self):
        authzrs = [gen_dom_authzr(domain="0", challs=acme_util.CHALLENGES)]
        mock_order = mock.MagicMock(authorizations=authzrs)
        self.mock_net.poll.side_effect = _gen_mock_on_poll(status=messages.STATUS_INVALID)

        with test_util.patch_display_util():
            with self.assertRaises(errors.AuthorizationError) as error:
                self.handler.handle_authorizations(mock_order, self.mock_config, False)
        self.assertIn('Some challenges have failed.', str(error.exception))
        self.assertEqual(self.mock_auth.cleanup.call_count, 1)
        self.assertEqual(
            self.mock_auth.cleanup.call_args[0][0][0].typ, "http-01")

    def test_best_effort(self):
        def _conditional_mock_on_poll(authzr):
            """This mock will invalidate one authzr, and invalidate the other one"""
            valid_mock = _gen_mock_on_poll(messages.STATUS_VALID)
            invalid_mock = _gen_mock_on_poll(messages.STATUS_INVALID)

            if authzr.body.identifier.value == 'will-be-invalid':
                return invalid_mock(authzr)
            return valid_mock(authzr)

        # Two authzrs. Only one will be valid.
        authzrs = [gen_dom_authzr(domain="will-be-valid", challs=acme_util.CHALLENGES),
                   gen_dom_authzr(domain="will-be-invalid", challs=acme_util.CHALLENGES)]
        self.mock_net.poll.side_effect = _conditional_mock_on_poll

        mock_order = mock.MagicMock(authorizations=authzrs)

        with mock.patch('certbot._internal.auth_handler.AuthHandler._report_failed_authzrs') \
            as mock_report:
            valid_authzr = self.handler.handle_authorizations(mock_order, self.mock_config, True)

        # Because best_effort=True, we did not blow up. Instead ...
        self.assertEqual(len(valid_authzr), 1)  # ... the valid authzr has been processed
        self.assertEqual(mock_report.call_count, 1)  # ... the invalid authzr has been reported

        self.mock_net.poll.side_effect = _gen_mock_on_poll(status=messages.STATUS_INVALID)

        with test_util.patch_display_util():
            with self.assertRaises(errors.AuthorizationError) as error:
                self.handler.handle_authorizations(mock_order, self.mock_config, True)

        # Despite best_effort=True, process will fail because no authzr is valid.
        self.assertIn('All challenges have failed.', str(error.exception))

    def test_validated_challenge_not_rerun(self):
        # With a pending challenge that is not supported by the plugin, we
        # expect an exception to be raised.
        authzr = acme_util.gen_authzr(
                messages.STATUS_PENDING, "0",
                [acme_util.DNS01],
                [messages.STATUS_PENDING], False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        self.assertRaises(
            errors.AuthorizationError, self.handler.handle_authorizations,
            mock_order, self.mock_config)

        # With a validated challenge that is not supported by the plugin, we
        # expect the challenge to not be solved again and
        # handle_authorizations() to succeed.
        authzr = acme_util.gen_authzr(
                messages.STATUS_VALID, "0",
                [acme_util.DNS01],
                [messages.STATUS_VALID], False)
        mock_order = mock.MagicMock(authorizations=[authzr])
        self.handler.handle_authorizations(mock_order, self.mock_config)

    def test_valid_authzrs_deactivated(self):
        """When we deactivate valid authzrs in an orderr, we expect them to become deactivated
        and to receive a list of deactivated authzrs in return."""
        def _mock_deactivate(authzr):
            if authzr.body.status == messages.STATUS_VALID:
                if authzr.body.identifier.value == "is_valid_but_will_fail":
                    raise acme_errors.Error("Mock deactivation ACME error")
                authzb = authzr.body.update(status=messages.STATUS_DEACTIVATED)
                authzr = messages.AuthorizationResource(body=authzb)
            else: # pragma: no cover
                raise errors.Error("Can't deactivate non-valid authz")
            return authzr

        to_deactivate = [("is_valid", messages.STATUS_VALID),
                         ("is_pending", messages.STATUS_PENDING),
                         ("is_valid_but_will_fail", messages.STATUS_VALID)]

        to_deactivate = [acme_util.gen_authzr(a[1], a[0], [acme_util.HTTP01],
                         [a[1], False]) for a in to_deactivate]
        orderr = mock.MagicMock(authorizations=to_deactivate)

        self.mock_net.deactivate_authorization.side_effect = _mock_deactivate

        authzrs, failed = self.handler.deactivate_valid_authorizations(orderr)

        self.assertEqual(self.mock_net.deactivate_authorization.call_count, 2)
        self.assertEqual(len(authzrs), 1)
        self.assertEqual(len(failed), 1)
        self.assertEqual(authzrs[0].body.identifier.value, "is_valid")
        self.assertEqual(authzrs[0].body.status, messages.STATUS_DEACTIVATED)
        self.assertEqual(failed[0].body.identifier.value, "is_valid_but_will_fail")
        self.assertEqual(failed[0].body.status, messages.STATUS_VALID)


def _gen_mock_on_poll(status=messages.STATUS_VALID, retry=0, wait_value=1):
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
        return updated_azr, mock.MagicMock(headers={'Retry-After': str(wait_value)})
    return _mock


class ChallbToAchallTest(unittest.TestCase):
    """Tests for certbot._internal.auth_handler.challb_to_achall."""

    def _call(self, challb):
        from certbot._internal.auth_handler import challb_to_achall
        return challb_to_achall(challb, "account_key", "domain")

    def test_it(self):
        self.assertEqual(
            self._call(acme_util.HTTP01_P),
            achallenges.KeyAuthorizationAnnotatedChallenge(
                challb=acme_util.HTTP01_P, account_key="account_key",
                domain="domain"),
        )


class GenChallengePathTest(unittest.TestCase):
    """Tests for certbot._internal.auth_handler.gen_challenge_path.

    .. todo:: Add more tests for dumb_path... depending on what we want to do.

    """
    def setUp(self):
        logging.disable(logging.FATAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @classmethod
    def _call(cls, challbs, preferences, combinations):
        from certbot._internal.auth_handler import gen_challenge_path
        return gen_challenge_path(challbs, preferences, combinations)

    def test_common_case(self):
        """Given DNS01 and HTTP01 with appropriate combos."""
        challbs = (acme_util.DNS01_P, acme_util.HTTP01_P)
        prefs = [challenges.DNS01, challenges.HTTP01]
        combos = ((0,), (1,))

        # Smart then trivial dumb path test
        self.assertEqual(self._call(challbs, prefs, combos), (0,))
        self.assertTrue(self._call(challbs, prefs, None))
        # Rearrange order...
        self.assertEqual(self._call(challbs[::-1], prefs, combos), (1,))
        self.assertTrue(self._call(challbs[::-1], prefs, None))

    def test_not_supported(self):
        challbs = (acme_util.DNS01_P, acme_util.HTTP01_P)
        prefs = [challenges.HTTP01]
        combos = ((0, 1),)

        # smart path fails because no challs in perfs satisfies combos
        self.assertRaises(
            errors.AuthorizationError, self._call, challbs, prefs, combos)
        # dumb path fails because all challbs are not supported
        self.assertRaises(
            errors.AuthorizationError, self._call, challbs, prefs, None)


class ReportFailedAuthzrsTest(unittest.TestCase):
    """Tests for certbot._internal.auth_handler.AuthHandler._report_failed_authzrs."""
    # pylint: disable=protected-access


    def setUp(self):
        from certbot._internal.auth_handler import AuthHandler

        self.mock_auth = mock.MagicMock(spec=plugin_common.Plugin, name="buzz")
        self.mock_auth.name = "buzz"
        self.mock_auth.auth_hint.return_value = "the buzz hint"
        self.handler = AuthHandler(self.mock_auth, mock.MagicMock(), mock.MagicMock(), [])

        kwargs = {
            "chall": acme_util.HTTP01,
            "uri": "uri",
            "status": messages.STATUS_INVALID,
            "error": messages.Error.with_code("tls", detail="detail"),
        }

        # Prevent future regressions if the error type changes
        self.assertIsNotNone(kwargs["error"].description)

        http_01 = messages.ChallengeBody(**kwargs)

        kwargs["chall"] = acme_util.HTTP01
        http_01 = messages.ChallengeBody(**kwargs)

        self.authzr1 = mock.MagicMock()
        self.authzr1.body.identifier.value = 'example.com'
        self.authzr1.body.challenges = [http_01, http_01]

        kwargs["error"] = messages.Error.with_code("dnssec", detail="detail")
        http_01_diff = messages.ChallengeBody(**kwargs)

        self.authzr2 = mock.MagicMock()
        self.authzr2.body.identifier.value = 'foo.bar'
        self.authzr2.body.challenges = [http_01_diff]

    @mock.patch('certbot._internal.auth_handler.display_util.notify')
    def test_same_error_and_domain(self, mock_notify):
        self.handler._report_failed_authzrs([self.authzr1])
        mock_notify.assert_called_with(
            '\n'
            'Certbot failed to authenticate some domains (authenticator: buzz). '
            'The Certificate Authority reported these problems:\n'
            '  Domain: example.com\n'
            '  Type:   tls\n'
            '  Detail: detail\n'
            '\n'
            '  Domain: example.com\n'
            '  Type:   tls\n'
            '  Detail: detail\n'
            '\nHint: the buzz hint\n'
        )

    @mock.patch('certbot._internal.auth_handler.display_util.notify')
    def test_different_errors_and_domains(self, mock_notify):
        self.mock_auth.name = "quux"
        self.mock_auth.auth_hint.return_value = "quuuuuux"
        self.handler._report_failed_authzrs([self.authzr1, self.authzr2])
        mock_notify.assert_called_with(
            '\n'
            'Certbot failed to authenticate some domains (authenticator: quux). '
            'The Certificate Authority reported these problems:\n'
            '  Domain: foo.bar\n'
            '  Type:   dnssec\n'
            '  Detail: detail\n'
            '\n'
            '  Domain: example.com\n'
            '  Type:   tls\n'
            '  Detail: detail\n'
            '\n'
            '  Domain: example.com\n'
            '  Type:   tls\n'
            '  Detail: detail\n'
            '\nHint: quuuuuux\n'
        )

    @mock.patch('certbot._internal.auth_handler.display_util.notify')
    def test_non_subclassed_authenticator(self, mock_notify):
        """If authenticator not derived from common.Plugin, we shouldn't call .auth_hint"""
        from certbot._internal.auth_handler import AuthHandler

        self.mock_auth = mock.MagicMock(name="quuz")
        self.mock_auth.name = "quuz"
        self.mock_auth.auth_hint.side_effect = Exception
        self.handler = AuthHandler(self.mock_auth, mock.MagicMock(), mock.MagicMock(), [])
        self.handler._report_failed_authzrs([self.authzr1])
        self.assertEqual(mock_notify.call_count, 1)


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
