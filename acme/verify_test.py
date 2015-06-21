"""Tests for acme.verify."""
import unittest

import mock
import requests

from acme import challenges


class SimpleHTTPSimpleVerifyTest(unittest.TestCase):
    """Tests for acme.verify.simple_http_simple_verify."""

    def setUp(self):
        self.chall = challenges.SimpleHTTP(token="foo")
        self.resp_http = challenges.SimpleHTTPResponse(path="bar", tls=False)
        self.resp_https = challenges.SimpleHTTPResponse(path="bar", tls=True)

    @classmethod
    def _call(cls, *args, **kwargs):
        from acme.verify import simple_http_simple_verify
        return simple_http_simple_verify(*args, **kwargs)

    @mock.patch("acme.verify.requests.get")
    def test_good_token(self, mock_get):
        for resp in self.resp_http, self.resp_https:
            mock_get.reset_mock()
            mock_get.return_value = mock.MagicMock(text=self.chall.token)
            self.assertTrue(self._call(resp, self.chall, "local"))
            mock_get.assert_called_once_with(resp.uri("local"), verify=False)

    @mock.patch("acme.verify.requests.get")
    def test_bad_token(self, mock_get):
        mock_get().text = self.chall.token + "!"
        self.assertFalse(self._call(self.resp_http, self.chall, "local"))

    @mock.patch("acme.verify.requests.get")
    def test_connection_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException
        self.assertFalse(self._call(self.resp_http, self.chall, "local"))


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
