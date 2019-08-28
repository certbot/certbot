import pytest

from certbot_integration_tests.apache_tests import context as apache_context


@pytest.fixture()
def context(request):
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = apache_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


def test_it(context):
    command = ['-d', 'apache.{0}.wtf'.format(context.worker_id)]
    context.certbot_test_apache(command)
