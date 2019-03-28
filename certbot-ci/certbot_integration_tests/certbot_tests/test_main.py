"""Module executing integration tests against certbot core."""
from __future__ import print_function
import os
import shutil
from os.path import join

import pytest
from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.certbot_tests.assertions import (
    assert_hook_execution, assert_save_renew_hook, assert_certs_count_for_lineage,
    assert_world_permissions, assert_equals_group_owner, assert_equals_permissions,
)
from certbot_integration_tests.utils import misc


@pytest.fixture()
def context(request):
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = certbot_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


def test_manual_dns_auth(context):
    """Test the DNS-01 challenge using manual plugin."""
    certname = context.get_domain('dns')
    context.certbot([
        '-a', 'manual', '-d', certname, '--preferred-challenges', 'dns',
        'run', '--cert-name', certname,
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook,
        '--pre-hook', 'echo wtf.pre >> "{0}"'.format(context.hook_probe),
        '--post-hook', 'echo wtf.post >> "{0}"'.format(context.hook_probe),
        '--renew-hook', 'echo renew >> "{0}"'.format(context.hook_probe)
    ])

    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'renew')
    assert_save_renew_hook(context.config_dir, certname)


def test_renew(context):
    """Test various certificate renew scenarios."""
    # First, we create a target certificate, with all hook dirs instantiated.
    # We should have a new certificate, with hooks executed.
    # Check also file permissions.
    certname = context.get_domain('renew')
    context.certbot([
        'certonly', '-d', certname, '--rsa-key-size', '4096',
        '--preferred-challenges', 'http-01'
    ])

    assert_certs_count_for_lineage(context.config_dir, certname, 1)
    assert_world_permissions(
        join(context.config_dir, 'archive/{0}/privkey1.pem'.format(certname)), 0)

    # Second, we force renew, and ensure that renewal hooks files are executed.
    # Also check that file permissions are correct.
    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.certbot(['renew'])

    assert_certs_count_for_lineage(context.config_dir, certname, 2)
    assert_hook_execution(context.hook_probe, 'deploy')
    assert_world_permissions(
        join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname)), 0)
    assert_equals_group_owner(
        join(context.config_dir, 'archive/{0}/privkey1.pem'.format(certname)),
        join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname)))
    assert_equals_permissions(
        join(context.config_dir, 'archive/{0}/privkey1.pem'.format(certname)),
        join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname)), 0o074)

    os.chmod(join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname)), 0o444)

    # Third, we try to renew without force.
    # It is not time, so no renew should occur, and no hooks should be executed.
    open(context.hook_probe, 'w').close()
    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.certbot_no_force_renew(['renew'])

    assert_certs_count_for_lineage(context.config_dir, certname, 2)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')
