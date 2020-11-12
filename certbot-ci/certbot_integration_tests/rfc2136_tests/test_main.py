"""Module executing integration tests against Certbot with the RFC2136 DNS authenticator."""
import pytest
import pkg_resources
import os.path
from shutil import copyfile

from certbot_integration_tests.rfc2136_tests import context as rfc2136_context


@pytest.fixture()
def context(request):
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = rfc2136_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


def test_get_certificate(context):
  creds_file = os.path.join(context.workspace, 'rfc2136-creds.ini')
  copyfile(
    pkg_resources.resource_filename('certbot_integration_tests',
                                    'assets/bind-config/rfc2136-credentials.ini'),
    creds_file
  )

  context.certbot_test_rfc2136([
    'certonly', '--dns-rfc2136-credentials', creds_file,
    '-d', 'example.com', '-d', '*.example.com', '--dry-run']
  )
