"""Plesk API client mock for easy unit testing"""
import mock
import pkg_resources
import os

from letsencrypt_plesk import api_client


class PleskApiMock(object):
    """Class helper for mock PleskApiClient"""

    def __init__(self):
        self.request = mock.MagicMock()
        self._request = None

    def expects_request(self, request):
        """Register a new expectation of the request"""
        with open(self._api_file(request)) as f:
            self._request = api_client.XmlToDict(f.read(), force_array=True)

    def will_response(self, response):
        """Stub by returning the response"""
        with open(self._api_file(response)) as f:
            self.request.return_value = api_client.XmlToDict(f.read())

    def assert_called(self):
        """Assert that API has met the expectations"""
        if self._request:
            self.request.assert_called_once_with(self._request)
        self._request = None

    @staticmethod
    def _api_file(filename):
        return pkg_resources.resource_filename(
            "letsencrypt_plesk.tests", os.path.join(
                "testdata", "api", filename + ".xml"))
