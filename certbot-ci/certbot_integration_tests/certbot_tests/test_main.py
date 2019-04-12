"""Module executing integration tests against certbot core."""
from __future__ import print_function
import os
import re
import shutil
import subprocess
from os.path import join, exists

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


def test_revoke_simple(context):
    """Test various scenarios that revokes a certificate."""
    # Default action after revoke is to delete the certificate.
    certname = context.get_domain()
    cert_path = join(context.config_dir, 'live/{0}/cert.pem'.format(certname))
    context.certbot(['-d', certname])
    context.certbot(['revoke', '--cert-path', cert_path, '--delete-after-revoke'])

    assert not exists(cert_path)

    # Check default deletion is overridden.
    certname = context.get_domain('le1')
    cert_path = join(context.config_dir, 'live/{0}/cert.pem'.format(certname))
    context.certbot(['-d', certname])
    context.certbot(['revoke', '--cert-path', cert_path, '--no-delete-after-revoke'])

    assert exists(cert_path)

    context.certbot(['delete', '--cert-name', certname])

    assert not exists(join(context.config_dir, 'archive/{0}'.format(certname)))
    assert not exists(join(context.config_dir, 'live/{0}'.format(certname)))
    assert not exists(join(context.config_dir, 'renewal/{0}.conf').format(certname))

    certname = context.get_domain('le2')
    key_path = join(context.config_dir, 'live/{0}/privkey.pem'.format(certname))
    cert_path = join(context.config_dir, 'live/{0}/cert.pem'.format(certname))
    context.certbot(['-d', certname])
    context.certbot(['revoke', '--cert-path', cert_path, '--key-path', key_path])


def test_revoke_and_unregister(context):
    """Test revoke with a reason then unregister."""
    cert1 = context.get_domain('le1')
    cert2 = context.get_domain('le2')
    cert3 = context.get_domain('le3')

    cert_path1 = join(context.config_dir, 'live/{0}/cert.pem'.format(cert1))
    key_path2 = join(context.config_dir, 'live/{0}/privkey.pem'.format(cert2))
    cert_path2 = join(context.config_dir, 'live/{0}/cert.pem'.format(cert2))

    context.certbot(['-d', cert1])
    context.certbot(['-d', cert2])
    context.certbot(['-d', cert3])

    context.certbot(['revoke', '--cert-path', cert_path1,
                    '--reason', 'cessationOfOperation'])
    context.certbot(['revoke', '--cert-path', cert_path2, '--key-path', key_path2,
                    '--reason', 'keyCompromise'])

    context.certbot(['unregister'])

    output = context.certbot(['certificates'])

    assert cert1 not in output
    assert cert2 not in output
    assert cert3 in output


def test_revoke_mutual_exclusive_flags(context):
    """Test --cert-path and --cert-name cannot be used during revoke."""
    cert = context.get_domain('le1')
    context.certbot(['-d', cert])
    with pytest.raises(subprocess.CalledProcessError) as error:
        context.certbot([
            'revoke', '--cert-name', cert,
            '--cert-path', join(context.config_dir, 'live/{0}/fullchain.pem'.format(cert))
        ])
        assert 'Exactly one of --cert-path or --cert-name must be specified' in error.out


def test_revoke_multiple_lineages(context):
    """Test revoke does not delete certs if multiple lineages share the same dir."""
    cert1 = context.get_domain('le1')
    context.certbot(['-d', cert1])

    assert os.path.isfile(join(context.config_dir, 'renewal/{0}.conf'.format(cert1)))

    cert2 = context.get_domain('le2')
    context.certbot(['-d', cert2])

    # Copy over renewal configuration of cert1 into renewal configuration of cert2.
    with open(join(context.config_dir, 'renewal/{0}.conf'.format(cert2)), 'r') as file:
        data = file.read()

    data = re.sub('archive_dir = .*{0}'.format(os.linesep),
                  'archive_dir = {0}{1}'.format(os.path.normpath(
                      join(context.config_dir, 'archive/{0}'.format(cert1))), os.linesep),
                  data)

    with open(join(context.config_dir, 'renewal/{0}.conf'.format(cert2)), 'w') as file:
        file.write(data)

    output = context.certbot([
        'revoke', '--cert-path', join(context.config_dir, 'live/{0}/cert.pem'.format(cert1))
    ])

    assert 'Not deleting revoked certs due to overlapping archive dirs' in output


def test_wildcard_certificates(context):
    """Test wildcard certificate issuance."""
    if context.acme_server == 'boulder-v1':
        pytest.skip('Wildcard certificates are not supported on ACME v1')

    certname = context.get_domain('wild')

    context.certbot([
        '-a', 'manual', '-d', '*.{0},{0}'.format(certname),
        '--preferred-challenge', 'dns',
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook
    ])

    assert exists(join(context.config_dir, 'live/{0}/fullchain.pem'.format(certname)))
