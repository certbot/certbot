"""Module executing integration tests against certbot with nginx plugin."""
import subprocess

import pytest

from certbot_integration_tests.nginx_tests import context as nginx_context


@pytest.fixture()
def context(request):
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = nginx_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


def test_nginx_version():
    print(subprocess.check_output(['nginx', '-v']))


@pytest.mark.parametrize('certname_pattern, params, set_default_server', [
    ('nginx.{0}.wtf', ['run'], True),
    ('nginx2.{0}.wtf', ['--preferred-challenges', 'http'], True),
    ('nginx3.{0}.wtf', ['--preferred-challenges', 'http'], True),
    ('nginx4.{0}.wtf', ['--preferred-challenges', 'http'], True),
    ('nginx5.{0}.wtf', ['--preferred-challenges', 'http'], False),
    ('nginx6.{0}.wtf,nginx7.{0}.wtf', ['--preferred-challenges', 'http'], False),
])
def test_certificate_deployment(certname_pattern, params, set_default_server, context):
    """
    Test various scenarios to deploy a certificate to nginx using certbot.
    """
    with context.nginx_server('default_server' if set_default_server else ''):
        certname = certname_pattern.format(context.worker_id)
        command = ['--domains', certname]
        command.extend(params)
        context.certbot_test_nginx(command)

        context.assert_deployment_and_rollback(certname.split(',')[0])
