"""Module executing integration tests against certbot core."""
from __future__ import print_function

import pytest

from certbot_integration_tests.certbot_tests.assertions import *
from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.utils import misc


@pytest.fixture()
def context(request):
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = certbot_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


def test_manual_http_auth(context):
    """Test the HTTP-01 challenge using manual plugin."""
    with misc.create_tcp_server(context.http_01_port) as webroot:
        manual_http_hooks = misc.manual_http_hooks(webroot)

        certname = context.wtf()
        context.certbot([
            'certonly', '-a', 'manual', '-d', certname,
            '--cert-name', certname,
            '--manual-auth-hook', manual_http_hooks[0],
            '--manual-cleanup-hook', manual_http_hooks[1],
            '--pre-hook', 'echo wtf.pre >> "{0}"'.format(context.hook_probe),
            '--post-hook', 'echo wtf.post >> "{0}"'.format(context.hook_probe),
            '--renew-hook', 'echo renew >> "{0}"'.format(context.hook_probe)
        ])

    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'renew')
    assert_save_renew_hook(context.config_dir, certname)
