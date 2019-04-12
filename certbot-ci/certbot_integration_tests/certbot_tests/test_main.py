"""Module executing integration tests against certbot core."""
from __future__ import print_function

import os
import subprocess
from os.path import join

import pytest
from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.certbot_tests.assertions import (
    assert_hook_execution, assert_save_renew_hook, assert_cert_count_for_lineage,
    assert_world_permissions, assert_equals_group_owner, assert_equals_permissions,
)
from certbot_integration_tests.utils import misc


def test_basic_commands(context):
    """Test simple commands on Certbot CLI."""
    # TMPDIR env variable is set to workspace for the certbot subprocess.
    # So tempdir module will create any temporary files/dirs in workspace,
    # and its content can be tested to check correct certbot cleanup.
    initial_count_tmpfiles = len(os.listdir(context.workspace))

    context.certbot(['--help'])
    context.certbot(['--help', 'all'])
    context.certbot(['--version'])

    with pytest.raises(subprocess.CalledProcessError):
        context.certbot(['--csr'])

    new_count_tmpfiles = len(os.listdir(context.workspace))
    assert initial_count_tmpfiles == new_count_tmpfiles


def test_hook_dirs_creation(context):
    """Test all hooks directory are created during Certbot startup."""
    context.certbot(['register'])

    for hook_dir in misc.list_renewal_hooks_dirs(context.config_dir):
        assert os.path.isdir(hook_dir)


def test_registration_override(context):
    """Test correct register/unregister, and registration override."""
    context.certbot(['register'])
    context.certbot(['unregister'])
    context.certbot(['register', '--email', 'ex1@domain.org,ex2@domain.org'])

    # TODO: When `certbot register --update-registration` is fully deprecated,
    #  delete the two following deprecated uses
    context.certbot(['register', '--update-registration', '--email', 'ex1@domain.org'])
    context.certbot(['register', '--update-registration', '--email', 'ex1@domain.org,ex2@domain.org'])

    context.certbot(['update_account', '--email', 'example@domain.org'])
    context.certbot(['update_account', '--email', 'ex1@domain.org,ex2@domain.org'])


def test_prepare_plugins(context):
    """Test that plugins are correctly instantiated and displayed."""
    output = context.certbot(['plugins', '--init', '--prepare'])

    assert 'webroot' in output


def test_http_01(context):
    """Test the HTTP-01 challenge using standalone plugin."""
    # We start a server listening on the port for the
    # TLS-SNI challenge to prevent regressions in #3601.
    with misc.create_http_server(context.tls_alpn_01_port):
        certname = context.get_domain('le2')
        context.certbot([
            '--domains', certname, '--preferred-challenges', 'http-01', 'run',
            '--cert-name', certname,
            '--pre-hook', 'echo wtf.pre >> "{0}"'.format(context.hook_probe),
            '--post-hook', 'echo wtf.post >> "{0}"'.format(context.hook_probe),
            '--deploy-hook', 'echo deploy >> "{0}"'.format(context.hook_probe)
        ])

    assert_hook_execution(context.hook_probe, 'deploy')
    assert_save_renew_hook(context.config_dir, certname)


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
