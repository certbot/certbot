"""Tests for certbot._internal.eff."""
import datetime
import sys
import unittest
from unittest import mock

import josepy
import pytest
import pytz
import requests

from acme import messages
from certbot._internal import account
from certbot._internal import constants
import certbot.tests.util as test_util

_KEY = josepy.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class SubscriptionTest(test_util.ConfigTestCase):
    """Abstract class for subscription tests."""
    def setUp(self):
        super().setUp()
        self.account = account.Account(
            regr=messages.RegistrationResource(
                uri=None, body=messages.Registration(),
                new_authzr_uri='hi'),
            key=_KEY,
            meta=account.Account.Meta(
                creation_host='test.certbot.org',
                creation_dt=datetime.datetime(
                    2015, 7, 4, 14, 4, 10, tzinfo=pytz.UTC)))
        self.config.email = 'certbot@example.org'
        self.config.eff_email = None


class PrepareSubscriptionTest(SubscriptionTest):
    """Tests for certbot._internal.eff.prepare_subscription."""
    def _call(self):
        from certbot._internal.eff import prepare_subscription
        prepare_subscription(self.config, self.account)

    @test_util.patch_display_util()
    @mock.patch("certbot._internal.eff.display_util.notify")
    def test_failure(self, mock_notify, mock_get_utility):
        self.config.email = None
        self.config.eff_email = True
        self._call()
        actual = mock_notify.call_args[0][0]
        expected_part = "because you didn't provide an e-mail address"
        assert expected_part in actual
        assert self.account.meta.register_to_eff is None

    @test_util.patch_display_util()
    def test_will_not_subscribe_with_no_prompt(self, mock_get_utility):
        self.config.eff_email = False
        self._call()
        self._assert_no_get_utility_calls(mock_get_utility)
        assert self.account.meta.register_to_eff is None

    @test_util.patch_display_util()
    def test_will_subscribe_with_no_prompt(self, mock_get_utility):
        self.config.eff_email = True
        self._call()
        self._assert_no_get_utility_calls(mock_get_utility)
        assert self.account.meta.register_to_eff == self.config.email

    @test_util.patch_display_util()
    def test_will_not_subscribe_with_prompt(self, mock_get_utility):
        mock_get_utility().yesno.return_value = False
        self._call()
        assert not mock_get_utility().add_message.called
        self._assert_correct_yesno_call(mock_get_utility)
        assert self.account.meta.register_to_eff is None

    @test_util.patch_display_util()
    def test_will_subscribe_with_prompt(self, mock_get_utility):
        mock_get_utility().yesno.return_value = True
        self._call()
        assert not mock_get_utility().add_message.called
        self._assert_correct_yesno_call(mock_get_utility)
        assert self.account.meta.register_to_eff == self.config.email

    def _assert_no_get_utility_calls(self, mock_get_utility):
        assert not mock_get_utility().yesno.called
        assert not mock_get_utility().add_message.called

    def _assert_correct_yesno_call(self, mock_get_utility):
        assert mock_get_utility().yesno.called
        call_args, call_kwargs = mock_get_utility().yesno.call_args
        actual = call_args[0]
        expected_part = 'Electronic Frontier Foundation'
        assert expected_part in actual
        assert not call_kwargs.get('default', True)


class HandleSubscriptionTest(SubscriptionTest):
    """Tests for certbot._internal.eff.handle_subscription."""
    def _call(self):
        from certbot._internal.eff import handle_subscription
        handle_subscription(self.config, self.account)

    @mock.patch('certbot._internal.eff.subscribe')
    def test_no_subscribe(self, mock_subscribe):
        self._call()
        assert mock_subscribe.called is False

    @mock.patch('certbot._internal.eff.subscribe')
    def test_subscribe(self, mock_subscribe):
        self.account.meta = self.account.meta.update(register_to_eff=self.config.email)
        self._call()
        assert mock_subscribe.called
        assert mock_subscribe.call_args[0][0] == self.config.email


class SubscribeTest(unittest.TestCase):
    """Tests for certbot._internal.eff.subscribe."""
    def setUp(self):
        self.email = 'certbot@example.org'
        self.json = {'status': True}
        self.response = mock.Mock(ok=True)
        self.response.json.return_value = self.json
        patcher = mock.patch("certbot._internal.eff.display_util.notify")
        self.mock_notify = patcher.start()
        self.addCleanup(patcher.stop)

    @mock.patch('certbot._internal.eff.requests.post')
    def _call(self, mock_post):
        mock_post.return_value = self.response

        from certbot._internal.eff import subscribe
        subscribe(self.email)
        self._check_post_call(mock_post)

    def _check_post_call(self, mock_post):
        assert mock_post.call_count == 1
        call_args, call_kwargs = mock_post.call_args
        assert call_args[0] == constants.EFF_SUBSCRIBE_URI

        data = call_kwargs.get('data')
        assert data is not None
        assert data.get('email') == self.email

    def test_bad_status(self):
        self.json['status'] = False
        self._call()
        actual = self._get_reported_message()
        expected_part = 'because your e-mail address appears to be invalid.'
        assert expected_part in actual

    def test_not_ok(self):
        self.response.ok = False
        self.response.raise_for_status.side_effect = requests.exceptions.HTTPError
        self._call()
        actual = self._get_reported_message()
        unexpected_part = 'because'
        assert unexpected_part not in actual

    def test_response_not_json(self):
        self.response.json.side_effect = ValueError()
        self._call()
        actual = self._get_reported_message()
        expected_part = 'problem'
        assert expected_part in actual

    def test_response_json_missing_status_element(self):
        self.json.clear()
        self._call()
        actual = self._get_reported_message()
        expected_part = 'problem'
        assert expected_part in actual

    def _get_reported_message(self):
        assert self.mock_notify.called
        return self.mock_notify.call_args[0][0]

    @test_util.patch_display_util()
    def test_subscribe(self, mock_get_utility):
        self._call()
        assert mock_get_utility.called is False


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
