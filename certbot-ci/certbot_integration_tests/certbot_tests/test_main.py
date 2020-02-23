"""Module executing integration tests against certbot core."""
from __future__ import print_function

import os
from os.path import exists
from os.path import join
import re
import shutil
import subprocess
import time

import pytest

from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.certbot_tests.assertions import assert_cert_count_for_lineage
from certbot_integration_tests.certbot_tests.assertions import assert_equals_group_owner
from certbot_integration_tests.certbot_tests.assertions import assert_equals_group_permissions
from certbot_integration_tests.certbot_tests.assertions import assert_equals_world_read_permissions
from certbot_integration_tests.certbot_tests.assertions import assert_hook_execution
from certbot_integration_tests.certbot_tests.assertions import assert_saved_renew_hook
from certbot_integration_tests.certbot_tests.assertions import assert_world_no_permissions
from certbot_integration_tests.certbot_tests.assertions import assert_world_read_permissions
from certbot_integration_tests.certbot_tests.assertions import EVERYBODY_SID
from certbot_integration_tests.utils import misc


@pytest.fixture()
def context(request):
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = certbot_context.IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


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
            '--pre-hook', misc.echo('wtf_pre', context.hook_probe),
            '--post-hook', misc.echo('wtf_post', context.hook_probe),
            '--deploy-hook', misc.echo('deploy', context.hook_probe),
        ])

    assert_hook_execution(context.hook_probe, 'deploy')
    assert_saved_renew_hook(context.config_dir, certname)


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
            '--pre-hook', misc.echo('wtf_pre', context.hook_probe),
            '--post-hook', misc.echo('wtf_post', context.hook_probe),
            '--renew-hook', misc.echo('renew', context.hook_probe),
        ])

    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'renew')
    assert_saved_renew_hook(context.config_dir, certname)


def test_manual_dns_auth(context):
    """Test the DNS-01 challenge using manual plugin."""
    certname = context.get_domain('dns')
    context.certbot([
        '-a', 'manual', '-d', certname, '--preferred-challenges', 'dns',
        'run', '--cert-name', certname,
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook,
        '--pre-hook', misc.echo('wtf_pre', context.hook_probe),
        '--post-hook', misc.echo('wtf_post', context.hook_probe),
        '--renew-hook', misc.echo('renew', context.hook_probe),
    ])

    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'renew')
    assert_saved_renew_hook(context.config_dir, certname)

    context.certbot(['renew', '--cert-name', certname, '--authenticator', 'manual'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)


def test_certonly(context):
    """Test the certonly verb on certbot."""
    context.certbot(['certonly', '--cert-name', 'newname', '-d', context.get_domain('newname')])


def test_auth_and_install_with_csr(context):
    """Test certificate issuance and install using an existing CSR."""
    certname = context.get_domain('le3')
    key_path = join(context.workspace, 'key.pem')
    csr_path = join(context.workspace, 'csr.der')

    misc.generate_csr([certname], key_path, csr_path)

    cert_path = join(context.workspace, 'csr', 'cert.pem')
    chain_path = join(context.workspace, 'csr', 'chain.pem')

    context.certbot([
        'auth', '--csr', csr_path,
        '--cert-path', cert_path,
        '--chain-path', chain_path
    ])

    print(misc.read_certificate(cert_path))
    print(misc.read_certificate(chain_path))

    context.certbot([
        '--domains', certname, 'install',
        '--cert-path', cert_path,
        '--key-path', key_path
    ])


def test_renew_files_permissions(context):
    """Test proper certificate file permissions upon renewal"""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    privkey1 = join(context.config_dir, 'archive', certname, 'privkey1.pem')
    privkey2 = join(context.config_dir, 'archive', certname, 'privkey2.pem')

    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    assert_world_no_permissions(privkey1)

    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_world_no_permissions(privkey2)
    assert_equals_group_owner(privkey1, privkey2)
    assert_equals_world_read_permissions(privkey1, privkey2)
    assert_equals_group_permissions(privkey1, privkey2)


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

    privkey1 = join(context.config_dir, 'archive', certname, 'privkey1.pem')
    privkey2 = join(context.config_dir, 'archive', certname, 'privkey2.pem')

    if os.name != 'nt':
        os.chmod(privkey1, 0o444)
    else:
        import win32security
        import ntsecuritycon
        # Get the current DACL of the private key
        security = win32security.GetFileSecurity(privkey1, win32security.DACL_SECURITY_INFORMATION)
        dacl = security.GetSecurityDescriptorDacl()
        # Create a read permission for Everybody group
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, everybody)
        # Apply the updated DACL to the private key
        security.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(privkey1, win32security.DACL_SECURITY_INFORMATION, security)

    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    if os.name != 'nt':
        # On Linux, read world permissions + all group permissions will be copied from the previous private key
        assert_world_read_permissions(privkey2)
        assert_equals_world_read_permissions(privkey1, privkey2)
        assert_equals_group_permissions(privkey1, privkey2)
    else:
        # On Windows, world will never have any permissions, and group permission is irrelevant for this platform
        assert_world_no_permissions(privkey2)


def test_graceful_renew_it_is_not_time(context):
    """Test graceful renew is not done when it is not due time."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    context.certbot(['renew', '--deploy-hook', misc.echo('deploy', context.hook_probe)],
                    force_renew=False)

    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')


def test_graceful_renew_it_is_time(context):
    """Test graceful renew is done when it is due time."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    with open(join(context.config_dir, 'renewal', '{0}.conf'.format(certname)), 'r') as file:
        lines = file.readlines()
    lines.insert(4, 'renew_before_expiry = 100 years{0}'.format(os.linesep))
    with open(join(context.config_dir, 'renewal', '{0}.conf'.format(certname)), 'w') as file:
        file.writelines(lines)

    context.certbot(['renew', '--deploy-hook', misc.echo('deploy', context.hook_probe)],
                    force_renew=False)

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_hook_execution(context.hook_probe, 'deploy')


def test_renew_with_changed_private_key_complexity(context):
    """Test proper renew with updated private key complexity."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname, '--rsa-key-size', '4096'])

    key1 = join(context.config_dir, 'archive', certname, 'privkey1.pem')
    assert os.stat(key1).st_size > 3000  # 4096 bits keys takes more than 3000 bytes
    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    context.certbot(['renew'])
    
    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    key2 = join(context.config_dir, 'archive', certname, 'privkey2.pem')
    assert os.stat(key2).st_size > 3000

    context.certbot(['renew', '--rsa-key-size', '2048'])

    assert_cert_count_for_lineage(context.config_dir, certname, 3)
    key3 = join(context.config_dir, 'archive', certname, 'privkey3.pem')
    assert os.stat(key3).st_size < 1800  # 2048 bits keys takes less than 1800 bytes


def test_renew_ignoring_directory_hooks(context):
    """Test hooks are ignored during renewal with relevant CLI flag."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

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
        '--pre-hook', misc.echo('pre', context.hook_probe),
        '--post-hook', misc.echo('post', context.hook_probe),
        '--deploy-hook', misc.echo('deploy', context.hook_probe),
    ])

    assert_hook_execution(context.hook_probe, 'pre')
    assert_hook_execution(context.hook_probe, 'post')
    assert_hook_execution(context.hook_probe, 'deploy')

    # Now we override all previous hooks during next renew.
    open(context.hook_probe, 'w').close()
    context.certbot([
        'renew', '--cert-name', certname,
        '--pre-hook', misc.echo('pre_override', context.hook_probe),
        '--post-hook', misc.echo('post_override', context.hook_probe),
        '--deploy-hook', misc.echo('deploy_override', context.hook_probe),
    ])

    assert_hook_execution(context.hook_probe, 'pre_override')
    assert_hook_execution(context.hook_probe, 'post_override')
    assert_hook_execution(context.hook_probe, 'deploy_override')
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'pre')
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'post')
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')

    # Expect that this renew will reuse new hooks registered in the previous renew.
    open(context.hook_probe, 'w').close()
    context.certbot(['renew', '--cert-name', certname])

    assert_hook_execution(context.hook_probe, 'pre_override')
    assert_hook_execution(context.hook_probe, 'post_override')
    assert_hook_execution(context.hook_probe, 'deploy_override')


def test_invalid_domain_with_dns_challenge(context):
    """Test certificate issuance failure with DNS-01 challenge."""
    # Manual dns auth hooks from misc are designed to fail if the domain contains 'fail-*'.
    domains = ','.join([context.get_domain('dns1'), context.get_domain('fail-dns1')])
    context.certbot([
        '-a', 'manual', '-d', domains,
        '--allow-subset-of-names',
        '--preferred-challenges', 'dns',
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook
    ])

    output = context.certbot(['certificates'])

    assert context.get_domain('fail-dns1') not in output


def test_reuse_key(context):
    """Test various scenarios where a key is reused."""
    certname = context.get_domain('reusekey')
    context.certbot(['--domains', certname, '--reuse-key'])
    context.certbot(['renew', '--cert-name', certname])

    with open(join(context.config_dir, 'archive/{0}/privkey1.pem').format(certname), 'r') as file:
        privkey1 = file.read()
    with open(join(context.config_dir, 'archive/{0}/privkey2.pem').format(certname), 'r') as file:
        privkey2 = file.read()
    assert privkey1 == privkey2

    context.certbot(['--cert-name', certname, '--domains', certname, '--force-renewal'])

    with open(join(context.config_dir, 'archive/{0}/privkey3.pem').format(certname), 'r') as file:
        privkey3 = file.read()
    assert privkey2 != privkey3

    with open(join(context.config_dir, 'archive/{0}/cert1.pem').format(certname), 'r') as file:
        cert1 = file.read()
    with open(join(context.config_dir, 'archive/{0}/cert2.pem').format(certname), 'r') as file:
        cert2 = file.read()
    with open(join(context.config_dir, 'archive/{0}/cert3.pem').format(certname), 'r') as file:
        cert3 = file.read()

    assert len({cert1, cert2, cert3}) == 3


def test_ecdsa(context):
    """Test certificate issuance with ECDSA key."""
    key_path = join(context.workspace, 'privkey-p384.pem')
    csr_path = join(context.workspace, 'csr-p384.der')
    cert_path = join(context.workspace, 'cert-p384.pem')
    chain_path = join(context.workspace, 'chain-p384.pem')

    misc.generate_csr([context.get_domain('ecdsa')], key_path, csr_path, key_type=misc.ECDSA_KEY_TYPE)
    context.certbot(['auth', '--csr', csr_path, '--cert-path', cert_path, '--chain-path', chain_path])

    certificate = misc.read_certificate(cert_path)
    assert 'ASN1 OID: secp384r1' in certificate


def test_ocsp_must_staple(context):
    """Test that OCSP Must-Staple is correctly set in the generated certificate."""
    if context.acme_server == 'pebble':
        pytest.skip('Pebble does not support OCSP Must-Staple.')

    certname = context.get_domain('must-staple')
    context.certbot(['auth', '--must-staple', '--domains', certname])

    certificate = misc.read_certificate(join(context.config_dir,
                                             'live/{0}/cert.pem').format(certname))
    assert 'status_request' in certificate or '1.3.6.1.5.5.7.1.24' in certificate


def test_revoke_simple(context):
    """Test various scenarios that revokes a certificate."""
    # Default action after revoke is to delete the certificate.
    certname = context.get_domain()
    cert_path = join(context.config_dir, 'live', certname, 'cert.pem')
    context.certbot(['-d', certname])
    context.certbot(['revoke', '--cert-path', cert_path, '--delete-after-revoke'])

    assert not exists(cert_path)

    # Check default deletion is overridden.
    certname = context.get_domain('le1')
    cert_path = join(context.config_dir, 'live', certname, 'cert.pem')
    context.certbot(['-d', certname])
    context.certbot(['revoke', '--cert-path', cert_path, '--no-delete-after-revoke'])

    assert exists(cert_path)

    context.certbot(['delete', '--cert-name', certname])

    assert not exists(join(context.config_dir, 'archive', certname))
    assert not exists(join(context.config_dir, 'live', certname))
    assert not exists(join(context.config_dir, 'renewal', '{0}.conf'.format(certname)))

    certname = context.get_domain('le2')
    key_path = join(context.config_dir, 'live', certname, 'privkey.pem')
    cert_path = join(context.config_dir, 'live', certname, 'cert.pem')
    context.certbot(['-d', certname])
    context.certbot(['revoke', '--cert-path', cert_path, '--key-path', key_path])


def test_revoke_and_unregister(context):
    """Test revoke with a reason then unregister."""
    cert1 = context.get_domain('le1')
    cert2 = context.get_domain('le2')
    cert3 = context.get_domain('le3')

    cert_path1 = join(context.config_dir, 'live', cert1, 'cert.pem')
    key_path2 = join(context.config_dir, 'live', cert2, 'privkey.pem')
    cert_path2 = join(context.config_dir, 'live', cert2, 'cert.pem')

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
            '--cert-path', join(context.config_dir, 'live', cert, 'fullchain.pem')
        ])
        assert 'Exactly one of --cert-path or --cert-name must be specified' in error.out


def test_revoke_multiple_lineages(context):
    """Test revoke does not delete certs if multiple lineages share the same dir."""
    cert1 = context.get_domain('le1')
    context.certbot(['-d', cert1])

    assert os.path.isfile(join(context.config_dir, 'renewal', '{0}.conf'.format(cert1)))

    cert2 = context.get_domain('le2')
    context.certbot(['-d', cert2])

    # Copy over renewal configuration of cert1 into renewal configuration of cert2.
    with open(join(context.config_dir, 'renewal', '{0}.conf'.format(cert2)), 'r') as file:
        data = file.read()

    data = re.sub('archive_dir = .*\n',
                  'archive_dir = {0}\n'.format(join(context.config_dir, 'archive', cert1).replace('\\', '\\\\')),
                  data)

    with open(join(context.config_dir, 'renewal', '{0}.conf'.format(cert2)), 'w') as file:
        file.write(data)

    output = context.certbot([
        'revoke', '--cert-path', join(context.config_dir, 'live', cert1, 'cert.pem')
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

    assert exists(join(context.config_dir, 'live', certname, 'fullchain.pem'))


def test_ocsp_status_stale(context):
    """Test retrieval of OCSP statuses for staled config"""
    sample_data_path = misc.load_sample_data_path(context.workspace)
    output = context.certbot(['certificates', '--config-dir', sample_data_path])

    assert output.count('TEST_CERT') == 2, ('Did not find two test certs as expected ({0})'
                                            .format(output.count('TEST_CERT')))
    assert output.count('EXPIRED') == 2, ('Did not find two expired certs as expected ({0})'
                                          .format(output.count('EXPIRED')))


def test_ocsp_status_live(context):
    """Test retrieval of OCSP statuses for live config"""
    cert = context.get_domain('ocsp-check')

    # OSCP 1: Check live certificate OCSP status (VALID)
    context.certbot(['--domains', cert])
    output = context.certbot(['certificates'])

    assert output.count('VALID') == 1, 'Expected {0} to be VALID'.format(cert)
    assert output.count('EXPIRED') == 0, 'Did not expect {0} to be EXPIRED'.format(cert)

    # OSCP 2: Check live certificate OCSP status (REVOKED)
    context.certbot(['revoke', '--cert-name', cert, '--no-delete-after-revoke'])
    # Sometimes in oldest tests (using openssl binary and not cryptography), the OCSP status is
    # not seen immediately by Certbot as invalid. Waiting few seconds solves this transient issue.
    time.sleep(5)
    output = context.certbot(['certificates'])

    assert output.count('INVALID') == 1, 'Expected {0} to be INVALID'.format(cert)
    assert output.count('REVOKED') == 1, 'Expected {0} to be REVOKED'.format(cert)


def test_dry_run_deactivate_authzs(context):
    """Test that Certbot deactivates authorizations when performing a dry run"""

    name = context.get_domain('dry-run-authz-deactivation')
    args = ['certonly', '--cert-name', name, '-d', name, '--dry-run']
    log_line = 'Recreating order after authz deactivation'

    # First order will not need deactivation
    context.certbot(args)
    with open(join(context.workspace, 'logs', 'letsencrypt.log'), 'r') as f:
        assert log_line not in f.read(), 'First order should not have had any authz reuse'

    # Second order will require deactivation
    context.certbot(args)
    with open(join(context.workspace, 'logs', 'letsencrypt.log'), 'r') as f:
        assert log_line in f.read(), 'Second order should have been recreated due to authz reuse'
