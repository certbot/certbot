"""Tests for certbot_dns_alwaysdata.dns_alwaysdata."""
import json
import os
import unittest

import mock
import requests

from certbot import errors
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

API_KEY = '0123456789abcdef'
ACCOUNT = 'foobar'


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    # pylint: disable=protected-access
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_alwaysdata.dns_alwaysdata import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({'alwaysdata_api_key': API_KEY, 'alwaysdata_account': ACCOUNT}, path)

        self.config = mock.MagicMock(alwaysdata_credentials=path,
                                     alwaysdata_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, 'alwaysdata')

        self.mock_client = mock.MagicMock()
        # _get_alwaysdata_client | pylint: disable=protected-access
        self.auth._get_alwaysdata_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)


class AlwaysdataClientTest(unittest.TestCase):
    # pylint: disable=protected-access
    record_name = '_acme-challenge.sub.example.com'
    record_content = 'whatever-challenge-value'
    record_ttl = 42

    def setUp(self):
        from certbot_dns_alwaysdata.dns_alwaysdata import _AlwaysdataClient
        self.client = _AlwaysdataClient(API_KEY, ACCOUNT)

    def mocked_send(self, *responses):
        """Build an ``adapter.send()`` returning :param:`responses` in sequence, one per call."""
        responses_iter = iter(responses)

        def side_effect(request, *args, **kwargs):
            # pylint: disable=unused-argument,missing-docstring
            item = next(responses_iter)
            if isinstance(item, Exception):
                raise item
            method, response = item
            self.assertEqual(method, request.method)
            return response

        return side_effect

    @classmethod
    def mocked_response(cls, status, json_data=None):
        """Build a mocked requests response."""
        resp = mock.Mock()
        resp.raise_for_status = mock.Mock()
        resp.status_code = status
        resp.ok = 200 <= status < 400
        resp.is_redirect = False
        resp.history = []
        resp.headers = mock.Mock()
        resp.headers.return_value = {}
        resp.raw._original_response.msg.get_all.return_value = []
        resp.json = mock.Mock()
        if json_data is not None:
            resp.json.return_value = json_data
        return resp

    @classmethod
    def json_data(cls, json_file):
        """Read JSON file in ``testdata``."""
        json_file = os.path.join(os.path.dirname(__file__), 'testdata', json_file)
        return json.load(open(json_file))

    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_add_txt_record(self, send_mock):
        get_mock = self.mocked_response(200, self.json_data('domain.json'))
        post_mock = self.mocked_response(201)
        send_mock.side_effect = self.mocked_send(('GET', get_mock), ('POST', post_mock))

        self.client.add_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.assertEqual(send_mock.call_count, 2)  # one GET, one POST
        self.assertEqual(post_mock.raise_for_status.call_count, 1)

    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_add_txt_record_http_error(self, send_mock):
        get_mock = self.mocked_response(200, self.json_data('domain.json'))
        exc = requests.Timeout()
        send_mock.side_effect = self.mocked_send(('GET', get_mock), exc)

        with self.assertRaisesRegexp(errors.PluginError, 'Error adding the TXT record'):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.assertEqual(send_mock.call_count, 2)  # one GET, one POST (the exception)

    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_del_txt_record(self, send_mock):
        get_domain_mock = self.mocked_response(200, self.json_data('domain.json'))
        get_record_mock = self.mocked_response(200, self.json_data('record.json')[:1])  # just one
        delete_mock = self.mocked_response(200)
        send_mock.side_effect = self.mocked_send(
            ('GET', get_domain_mock), ('GET', get_record_mock), ('DELETE', delete_mock))

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.assertEqual(send_mock.call_count, 3)  # two GETs, one DELETE
        self.assertEqual(get_domain_mock.raise_for_status.call_count, 0)
        self.assertEqual(get_domain_mock.json.call_count, 1)
        self.assertEqual(get_record_mock.raise_for_status.call_count, 1)
        self.assertEqual(get_record_mock.json.call_count, 1)
        self.assertEqual(delete_mock.raise_for_status.call_count, 1)
        self.assertEqual(delete_mock.json.call_count, 0)

    @mock.patch('logging.Logger.warning')
    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_del_txt_record_no_record(self, send_mock, log_mock):
        get_domain_mock = self.mocked_response(200, self.json_data('domain.json'))
        get_record_mock = self.mocked_response(200, [])  # zero records
        send_mock.side_effect = self.mocked_send(('GET', get_domain_mock), ('GET', get_record_mock))

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.assertEqual(send_mock.call_count, 2)  # two GETs
        log_mock.assert_called_with('No matching TXT record to delete, skipping cleanup')

    @mock.patch('logging.Logger.warning')
    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_del_txt_record_too_many_records(self, send_mock, log_mock):
        get_domain_mock = self.mocked_response(200, self.json_data('domain.json'))
        get_record_mock = self.mocked_response(200, self.json_data('record.json'))
        send_mock.side_effect = self.mocked_send(('GET', get_domain_mock), ('GET', get_record_mock))

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.assertEqual(send_mock.call_count, 2)  # two GET
        self.assertEqual(get_domain_mock.raise_for_status.call_count, 0)
        self.assertEqual(get_domain_mock.json.call_count, 1)
        self.assertEqual(get_record_mock.raise_for_status.call_count, 1)
        self.assertEqual(get_record_mock.json.call_count, 1)
        log_mock.assert_called_with('Too many matching TXT records to delete, skipping cleanup')

    @mock.patch('logging.Logger.warning')
    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_del_txt_record_search_http_error(self, send_mock, log_mock):
        get_domain_mock = self.mocked_response(200, self.json_data('domain.json'))
        exc = requests.Timeout()
        send_mock.side_effect = self.mocked_send(('GET', get_domain_mock), exc)

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.assertEqual(send_mock.call_count, 2)  # two GETs (including one exception)
        log_mock.assert_called_with(
            "Encountered error searching TXT record to delete, skipping cleanup: %s", exc)

    @mock.patch('logging.Logger.warning')
    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_del_txt_record_delete_http_error(self, send_mock, log_mock):
        get_domain_mock = self.mocked_response(200, self.json_data('domain.json'))
        get_record_mock = self.mocked_response(200, self.json_data('record.json')[:1])  # just one
        exc = requests.Timeout()
        send_mock.side_effect = self.mocked_send(
            ('GET', get_domain_mock), ('GET', get_record_mock), exc)

        self.client.del_txt_record(DOMAIN, self.record_name, self.record_content, self.record_ttl)

        self.assertEqual(send_mock.call_count, 3)  # two GETs, one DELETE (the exception)
        log_mock.assert_called_with(
            "Encountered error deleting TXT record, skipping cleanup: %s", exc)

    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_find_domain(self, send_mock):
        get_mock = self.mocked_response(200, self.json_data('domain.json'))
        send_mock.side_effect = self.mocked_send(('GET', get_mock))

        self.client._find_alwaysdata_domain(DOMAIN)

        self.assertEqual(send_mock.call_count, 1)
        # errors are ignored in domain search
        self.assertEqual(get_mock.raise_for_status.call_count, 0)
        self.assertEqual(get_mock.json.call_count, 1)

    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_find_domain_http_error(self, send_mock):
        send_mock.side_effect = self.mocked_send(requests.Timeout())

        with self.assertRaisesRegexp(errors.PluginError, 'Encountered error finding'):
            self.client._find_alwaysdata_domain('sub.doesnotexist.tld')

    @mock.patch('requests.adapters.HTTPAdapter.send')
    def test_find_domain_no_results(self, send_mock):
        get_mock = self.mocked_response(200, [])
        send_mock.side_effect = self.mocked_send(*(('GET', get_mock),) * 3)

        with self.assertRaisesRegexp(errors.PluginError, 'Unable to determine domain'):
            self.client._find_alwaysdata_domain('sub.doesnotexist.tld')

        self.assertEqual(send_mock.call_count, 3)  # sub., doesnotexist., tld.
        self.assertEqual(get_mock.json.call_count, 3)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
