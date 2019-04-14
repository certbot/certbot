"""Module executing integration tests against certbot core."""
from __future__ import print_function
import os
import shutil
from os.path import join

import pytest
from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.certbot_tests.assertions import (
    assert_hook_execution, assert_save_renew_hook, assert_cert_count_for_lineage,
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


def test_manual_http_auth(context):
    """Test the HTTP-01 challenge using manual plugin."""
    with misc.create_http_server(context.http_01_port) as webroot,\
            misc.manual_http_hooks(webroot, context.http_01_port) as scripts:

        certname = context.get_domain()
        context.certbot([
            'certonly', '-a', 'manual', '-d', certname,
            '--cert-name', certname,
            '--manual-auth-hook', scripts[0],
            '--manual-cleanup-hook', scripts[1],
            '--pre-hook', 'echo wtf.pre >> "{0}"'.format(context.hook_probe),
            '--post-hook', 'echo wtf.post >> "{0}"'.format(context.hook_probe),
            '--deploy-hook', 'echo deploy >> "{0}"'.format(context.hook_probe)
        ])

    assert_hook_execution(context.hook_probe, 'deploy')
    assert_save_renew_hook(context.config_dir, certname)


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

    context.certbot(['renew', '--cert-name', certname, '--authenticator', 'manual'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)


def test_renew_files_permissions(context):
    """Test proper certificate file permissions upon renewal"""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    assert_world_permissions(
        join(context.config_dir, 'archive', certname, 'privkey1.pem'), 0)

    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_world_permissions(
        join(context.config_dir, 'archive', certname, 'privkey2.pem'), 0)
    assert_equals_group_owner(
        join(context.config_dir, 'archive', certname, 'privkey1.pem'),
        join(context.config_dir, 'archive', certname, 'privkey2.pem'))
    assert_equals_permissions(
        join(context.config_dir, 'archive', certname, 'privkey1.pem'),
        join(context.config_dir, 'archive', certname, 'privkey2.pem'), 0o074)


def test_renew_with_hook_scripts(context):
    """Test certificate renewal with script hooks."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_hook_execution(context.hook_probe, 'deploy')


def test_renew_files_propagate_permissions(context):
    """Test proper certificate renewal with custom permissions propagated on private key."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    os.chmod(join(context.config_dir, 'archive/{0}/privkey1.pem'.format(certname)), 0o444)
    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_equals_permissions(
        join(context.config_dir, 'archive/{0}/privkey1.pem'.format(certname)),
        join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname)), 0o074)


def test_graceful_renew_it_is_not_time(context):
    """Test graceful renew is not done when it is not due time."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    context.certbot_no_force_renew([
        'renew', '--deploy-hook', 'echo deploy >> "{0}"'.format(context.hook_probe)])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')


def test_graceful_renew_it_is_time(context):
    """Test graceful renew is done when it is due time."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    with open(join(context.config_dir, 'renewal/{0}.conf'.format(certname)), 'r') as file:
        lines = file.readlines()
    lines.insert(4, 'renew_before_expiry = 100 years{0}'.format(os.linesep))
    with open(join(context.config_dir, 'renewal/{0}.conf'.format(certname)), 'w') as file:
        file.writelines(lines)

    context.certbot_no_force_renew([
        'renew', '--deploy-hook', 'echo deploy >> "{0}"'.format(context.hook_probe)])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_hook_execution(context.hook_probe, 'deploy')


def test_renew_with_changed_private_key_complexity(context):
    """Test proper renew with updated private key complexity."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname, '--rsa-key-size', '4096'])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    context.certbot(['renew'])
    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    key2 = join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname))
    assert os.stat(key2).st_size > 3000  # 4096 bits keys takes more than 3000 bytes

    context.certbot(['renew', '--rsa-key-size', '2048'])

    assert_cert_count_for_lineage(context.config_dir, certname, 3)
    key3 = join(context.config_dir, 'archive/{0}/privkey3.pem'.format(certname))
    assert os.stat(key3).st_size < 1800  # 2048 bits keys takes less than 1800 bytes


def test_renew_ignoring_directory_hooks(context):
    """Test hooks are ignored during renewal with relevant CLI flag."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    # Force renew. Assert certificate renewal and hook scripts execution.
    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.certbot(['renew', '--no-directory-hooks'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')


def test_renew_empty_hook_scripts(context):
    """Test proper renew with empty hook scripts."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    for hook_dir in misc.list_renewal_hooks_dirs(context.config_dir):
        shutil.rmtree(hook_dir)
        os.makedirs(join(hook_dir, 'dir'))
        open(join(hook_dir, 'file'), 'w').close()
    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)


def test_renew_hook_override(context):
    """Test correct hook override on renew."""
    certname = context.get_domain('override')
    context.certbot([
        'certonly', '-d', certname,
        '--preferred-challenges', 'http-01',
        '--pre-hook', 'echo pre >> "{0}"'.format(context.hook_probe),
        '--post-hook', 'echo post >> "{0}"'.format(context.hook_probe),
        '--deploy-hook', 'echo deploy >> "{0}"'.format(context.hook_probe)
    ])

    assert_hook_execution(context.hook_probe, 'pre')
    assert_hook_execution(context.hook_probe, 'post')
    assert_hook_execution(context.hook_probe, 'deploy')

    # Now we override all previous hooks during next renew.
    open(context.hook_probe, 'w').close()
    context.certbot([
        'renew', '--cert-name', certname,
        '--pre-hook', 'echo pre-override >> "{0}"'.format(context.hook_probe),
        '--post-hook', 'echo post-override >> "{0}"'.format(context.hook_probe),
        '--deploy-hook', 'echo deploy-override >> "{0}"'.format(context.hook_probe)
    ])

    assert_hook_execution(context.hook_probe, 'pre-override')
    assert_hook_execution(context.hook_probe, 'post-override')
    assert_hook_execution(context.hook_probe, 'deploy-override')
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'pre')
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'post')
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')

    # Expect that this renew will reuse new hooks registered in the previous renew.
    open(context.hook_probe, 'w').close()
    context.certbot(['renew', '--cert-name', certname])

    assert_hook_execution(context.hook_probe, 'pre-override')
    assert_hook_execution(context.hook_probe, 'post-override')
    assert_hook_execution(context.hook_probe, 'deploy-override')
