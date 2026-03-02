"""Module executing integration tests against certbot with nginx plugin."""
import os
import ssl
from typing import Generator

import pytest

from certbot_integration_tests.nginx_tests.context import IntegrationTestsContext


@pytest.fixture(name='context')
def test_context(request: pytest.FixtureRequest) -> Generator[IntegrationTestsContext, None, None]:
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


@pytest.mark.parametrize('certname_pattern, params, context', [
    ('nginx.{0}.wtf', ['run'], {'default_server': True}),
    ('nginx2.{0}.wtf', ['--preferred-challenges', 'http'], {'default_server': True}),
    # Overlapping location block and server-block-level return 301
    ('nginx3.{0}.wtf', ['--preferred-challenges', 'http'], {'default_server': True}),
    # No matching server block; default_server exists
    ('nginx4.{0}.wtf', ['--preferred-challenges', 'http'], {'default_server': True}),
    # No matching server block; default_server does not exist
    ('nginx5.{0}.wtf', ['--preferred-challenges', 'http'], {'default_server': False}),
    # Multiple domains, mix of matching and not
    ('nginx6.{0}.wtf,nginx7.{0}.wtf', [
        '--preferred-challenges', 'http'
    ], {'default_server': False}),
], indirect=['context'])
def test_certificate_deployment(certname_pattern: str, params: list[str],
                                context: IntegrationTestsContext) -> None:
    """
    Test various scenarios to deploy a certificate to nginx using certbot.
    """
    domains = certname_pattern.format(context.worker_id)
    command = ['--domains', domains]
    command.extend(params)
    context.certbot_test_nginx(command)

    lineage = domains.split(',')[0]
    server_cert = ssl.get_server_certificate(('localhost', context.https_port))
    with open(os.path.join(
        context.workspace, 'conf/live/{0}/cert.pem'.format(lineage)), 'r'
    ) as file:
        certbot_cert = file.read()

    assert server_cert == certbot_cert

    context.certbot_test_nginx(['rollback', '--checkpoints', '1'])

    with open(context.nginx_config_path, 'r') as file_h:
        current_nginx_config = file_h.read()

    assert context.nginx_config == current_nginx_config
