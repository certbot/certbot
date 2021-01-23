"""Module executing integration tests against Certbot with the RFC2136 DNS authenticator."""
import pytest

from certbot_integration_tests.rfc2136_tests import context as rfc2136_context


@pytest.fixture(name="context")
def pytest_context(request):
    # pylint: disable=missing-function-docstring
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = rfc2136_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


@pytest.mark.parametrize('domain', [('example.com'), ('sub.example.com')])
def test_get_certificate(domain, context):
    context.skip_if_no_bind9_server()

    with context.rfc2136_credentials() as creds:
        context.certbot_test_rfc2136([
            'certonly', '--dns-rfc2136-credentials', creds,
            '-d', domain, '-d', '*.{}'.format(domain)
        ])
