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


def test_renew_files_permissions(context):
    """Test certificate file permissions upon renewal"""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    assert_world_permissions(
        join(context.config_dir, 'archive', certname, 'privkey1.pem'), 0)

    # Force renew. Assert certificate renewal and proper permissions.
    # We assert certificate renewal and proper permissions.
    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_world_permissions(
        join(context.config_dir, 'archive', certname, '/privkey2.pem'), 0)
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

    # Force renew. Assert certificate renewal and hook scripts execution.
    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_hook_execution(context.hook_probe, 'deploy')


def test_ocsp_status(context):
    """Test retrieval of OCSP statuses."""
    if context.acme_server == 'pebble':
        pytest.skip('Pebble does not support OCSP status requests.')

    # OCSP 1: Check stale OCSP status
    sample_data_path = misc.load_sample_data_path(context.workspace)
    output = context.certbot(['certificates', '--config-dir', sample_data_path])

    assert output.count('TEST_CERT') == 2, ('Did not find two test certs as expected ({0})'
                                            .format(output.count('TEST_CERT')))
    assert output.count('EXPIRED') == 2, ('Did not find two expired certs as expected ({0})'
                                          .format(output.count('EXPIRED')))

    # OSCP 2: Check live certificate OCSP status (VALID)
    cert = context.get_domain('ocsp-check')
    context.certbot(['--domains', cert])
    output = context.certbot(['certificates'])

    assert output.count('VALID') == 1, 'Expected {0} to be VALID'.format(cert)
    assert output.count('EXPIRED') == 0, 'Did not expect {0} to be EXPIRED'.format(cert)

    # OSCP 3: Check live certificate OCSP status (REVOKED)
    context.certbot(['revoke', '--cert-name', cert, '--no-delete-after-revoke'])
    output = context.certbot(['certificates'])

    assert output.count('INVALID') == 1, 'Expected {0} to be INVALID'.format(cert)
    assert output.count('REVOKED') == 1, 'Expected {0} to be REVOKED'.format(cert)
