"""Module executing integration tests against certbot with nginx plugin."""
import os
import ssl

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


@pytest.mark.parametrize('certname_pattern, params, context', [
    # Passing True as third level makes the context fixture start Nginx with a default server.
    ('nginx.{0}.wtf', ['run'], True),
    ('nginx2.{0}.wtf', ['--preferred-challenges', 'http'], True),
    # Overlapping location block and server-block-level return 301
    ('nginx3.{0}.wtf', ['--preferred-challenges', 'http'], True),
    # No matching server block; default_server exists
    ('nginx4.{0}.wtf', ['--preferred-challenges', 'http'], True),
    # No default server in Nginx starting to this point.
    ('nginx5.{0}.wtf', ['--preferred-challenges', 'http'], False),
    # Multiple domains, mix of matching and not
    ('nginx6.{0}.wtf,nginx7.{0}.wtf', ['--preferred-challenges', 'http'], False),
], indirect=['context'])
def test_certificate_deployment(certname_pattern, params, context):
    """
    Test various scenarios to deploy a certificate to nginx using certbot.
    """
    domains = certname_pattern.format(context.worker_id)
    command = ['--domains', domains]
    command.extend(params)
    context.certbot_test_nginx(command)

    lineage = domains.split(',')[0]
    server_cert = ssl.get_server_certificate(('localhost', context.tls_alpn_01_port))
    with open(os.path.join(context.workspace, 'conf/live/{0}/cert.pem'.format(lineage)), 'r') as file:
        certbot_cert = file.read()

    assert server_cert == certbot_cert

    command = ['--authenticator', 'nginx', '--installer', 'nginx',
               '--nginx-server-root', context.nginx_root,
               'rollback', '--checkpoints', '1']
    context._common_test_no_force_renew(command)

    with open(context.nginx_config_path, 'r') as file_h:
        current_nginx_config = file_h.read()

    assert context.nginx_config == current_nginx_config
