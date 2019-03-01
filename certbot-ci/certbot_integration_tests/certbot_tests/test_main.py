import requests
import urllib3

import pytest

from certbot_integration_tests.certbot_tests import context as certbot_context


@pytest.fixture()
def context(request):
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = certbot_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


def test_hello_1(context):
    assert context.http_01_port
    assert context.tls_alpn_01_port
    try:
        response = requests.get(context.directory_url, verify=False)
        response.raise_for_status()
        assert response.json()
        response.close()
    except urllib3.exceptions.InsecureRequestWarning:
        pass


def test_hello_2(context):
    assert context.http_01_port
    assert context.tls_alpn_01_port
    try:
        response = requests.get(context.directory_url, verify=False)
        response.raise_for_status()
        assert response.json()
        response.close()
    except urllib3.exceptions.InsecureRequestWarning:
        pass
