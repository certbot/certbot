import ssl

import pytest
from six.moves.urllib.request import urlopen


@pytest.mark.incremental
class TestSuite(object):

    def test_directory_accessibility(self, acme_url):
        context = ssl.SSLContext()
        urlopen(acme_url, context=context)

    def test_will_fail(selfs):
        assert False

    def test_should_success(self):
        assert True
