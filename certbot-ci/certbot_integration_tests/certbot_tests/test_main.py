from __future__ import print_function
import subprocess
import shutil
import re
import os
from os.path import join, exists

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


def test_basic_commands(context):
    # TMPDIR env variable is set to workspace for the certbot subprocess.
    # So tempdir module will create any temporary files/dirs in workspace,
    # and its content can be tested to check correct certbot cleanup.
    initial_count_tmpfiles = len(os.listdir(context.workspace))

    context.common(['--help'])
    context.common(['--help', 'all'])
    context.common(['--version'])

    with pytest.raises(subprocess.CalledProcessError):
        context.common(['--csr'])

    new_count_tmpfiles = len(os.listdir(context.workspace))
    assert initial_count_tmpfiles == new_count_tmpfiles


def test_hook_dirs_creation(context):
    context.common(['register'])

    for hook_dir in misc.list_renewal_hooks_dirs(context.config_dir):
        assert os.path.isdir(hook_dir)


def test_registration_override(context):
    context.common(['register'])
    context.common(['unregister'])
    context.common(['register', '--email', 'ex1@domain.org,ex2@domain.org'])

    # TODO: When `certbot register --update-registration` is fully deprecated,
    #  delete the two following deprecated uses
    context.common(['register', '--update-registration', '--email', 'ex1@domain.org'])
    context.common(['register', '--update-registration', '--email', 'ex1@domain.org,ex2@domain.org'])

    context.common(['update_account', '--email', 'example@domain.org'])
    context.common(['update_account', '--email', 'ex1@domain.org,ex2@domain.org'])


def test_prepare_plugins(context):
    output = context.common(['plugins', '--init', '--prepare'])

    assert 'webroot' in output


def test_http_01(context):
    with misc.create_tcp_server(context.tls_alpn_01_port):
        certname = context.wtf('le2')
        context.common([
            '--domains', certname, '--preferred-challenges', 'http-01', 'run',
            '--cert-name', certname,
            '--pre-hook', 'echo wtf.pre >> "{0}"'.format(context.hook_probe),
            '--post-hook', 'echo wtf.post >> "{0}"'.format(context.hook_probe),
            '--deploy-hook', 'echo deploy >> "{0}"'.format(context.hook_probe)
        ])

    assert_hook_execution(context.hook_probe, 'deploy')
    assert_save_renew_hook(context.config_dir, certname)


def test_manual_http_auth(context):
    with misc.create_tcp_server(context.http_01_port) as webroot:
        manual_http_hooks = misc.manual_http_hooks(webroot)

        certname = context.wtf()
        context.common([
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


def test_manual_dns_auth(context):
    certname = context.wtf('dns')
    context.common([
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


def test_certonly(context):
    context.common(['certonly', '--cert-name', 'newname', '-d', context.wtf('newname')])


def test_auth_and_install_with_csr(context):
    certname = context.wtf('le3')
    key_path = join(context.workspace, 'key.pem')
    csr_path = join(context.workspace, 'csr.der')

    misc.generate_csr([certname], key_path, csr_path)

    cert_path = join(context.workspace, 'csr/cert.pem')
    chain_path = join(context.workspace, 'csr/chain.pem')

    context.common([
        'auth', '--csr', csr_path,
        '--cert-path', cert_path,
        '--chain-path', chain_path
    ])

    print(misc.read_certificate(cert_path))
    print(misc.read_certificate(chain_path))

    context.common([
        '--domains', certname, 'install',
        '--cert-path', cert_path,
        '--key-path', key_path
    ])


def test_renew(context):
    # First, we create a target certificate, with all hook dirs instantiated.
    # We should have a new certificate, with hooks executed.
    # Check also file permissions.
    certname = context.wtf('renew')
    context.common([
        'certonly', '-d', certname, '--rsa-key-size', '4096',
        '--preferred-challenges', 'http-01'
    ])

    assert_certs_count_for_lineage(context.config_dir, certname, 1)
    assert_world_permissions(
        join(context.config_dir, 'archive/{0}/privkey1.pem'.format(certname)), 0)

    # Second, we force renew, and ensure that renewal hooks files are executed.
    # Also check that file permissions are correct.
    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.common(['renew'])

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
    context.common_no_force_renew(['renew'])

    assert_certs_count_for_lineage(context.config_dir, certname, 2)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')

    # Fourth, we modify the time when renew occur to 4 years before expiration.
    # When trying renew without force, then renew should occur for this large time.
    # Also we specify to not use hooks dir, so no hook should be run during this renew.
    # Also this renew should use explicitly a 2048 key size.
    # And finally we check the file permissions.
    open(context.hook_probe, 'w').close()
    with open(join(context.config_dir, 'renewal/{0}.conf'.format(certname)), 'r') as file:
        lines = file.readlines()
    lines.insert(4, 'renew_before_expiry = 100 years{0}'.format(os.linesep))
    with open(join(context.config_dir, 'renewal/{0}.conf'.format(certname)), 'w') as file:
        file.writelines(lines)
    context.common_no_force_renew(['renew', '--no-directory-hooks',
                                   '--rsa-key-size', '2048'])

    assert_certs_count_for_lineage(context.config_dir, certname, 3)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')
    key2 = join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname))
    key3 = join(context.config_dir, 'archive/{0}/privkey3.pem'.format(certname))
    assert os.stat(key2).st_size > 3000  # 4096 bits keys takes more than 3000 bytes
    assert os.stat(key3).st_size < 1800  # 2048 bits keys takes less than 1800 bytes

    assert_world_permissions(
        join(context.config_dir, 'archive/{0}/privkey3.pem'.format(certname)), 4)
    assert_equals_group_owner(
        join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname)),
        join(context.config_dir, 'archive/{0}/privkey3.pem'.format(certname)))
    assert_equals_permissions(
        join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname)),
        join(context.config_dir, 'archive/{0}/privkey3.pem'.format(certname)), 0o074)

    # Fifth, we clean every dir hook, and replace their content by empty dir and empty files.
    # Everything should renew correctly.
    for hook_dir in misc.list_renewal_hooks_dirs(context.config_dir):
        shutil.rmtree(hook_dir)
        os.makedirs(join(hook_dir, 'dir'))
        open(join(hook_dir, 'file'), 'w').close()
    context.common(['renew'])

    assert_certs_count_for_lineage(context.config_dir, certname, 4)


def test_hook_override(context):
    certname = context.wtf('override')
    context.common([
        'certonly', '-d', certname,
        '--preferred-challenges', 'http-01',
        '--pre-hook', 'echo pre >> "{0}"'.format(context.hook_probe),
        '--post-hook', 'echo post >> "{0}"'.format(context.hook_probe),
        '--deploy-hook', 'echo deploy >> "{0}"'.format(context.hook_probe)
    ])

    assert_hook_execution(context.hook_probe, 'pre')
    assert_hook_execution(context.hook_probe, 'post')
    assert_hook_execution(context.hook_probe, 'deploy')

    open(context.hook_probe, 'w').close()
    context.common([
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

    open(context.hook_probe, 'w').close()
    context.common(['renew', '--cert-name', certname])

    assert_hook_execution(context.hook_probe, 'pre-override')
    assert_hook_execution(context.hook_probe, 'post-override')
    assert_hook_execution(context.hook_probe, 'deploy-override')


def test_invalid_domain_with_dns_challenge(context):
    certs = ','.join([context.wtf('dns1'), context.wtf('fail-dns1')])
    context.common([
        '-a', 'manual', '-d', certs,
        '--allow-subset-of-names',
        '--preferred-challenges', 'dns',
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook
    ])

    output = context.common(['certificates'])

    assert context.wtf('fail-dns1') not in output


def test_reuse_key(context):
    certname = context.wtf('reusekey')
    context.common(['--domains', certname, '--reuse-key'])
    context.common(['renew', '--cert-name', certname])

    with open(join(context.config_dir, 'archive/{0}/privkey1.pem').format(certname), 'r') as file:
        privkey1 = file.read()
    with open(join(context.config_dir, 'archive/{0}/privkey2.pem').format(certname), 'r') as file:
        privkey2 = file.read()
    assert privkey1 == privkey2

    context.common(['--cert-name', certname, '--domains', certname, '--force-renewal'])

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
    key_path = join(context.workspace, 'privkey-p384.pem')
    csr_path = join(context.workspace, 'csr-p384.der')
    cert_path = join(context.workspace, 'cert-p384.pem')
    chain_path = join(context.workspace, 'chain-p384.pem')

    misc.generate_csr([context.wtf('ecdsa')], key_path, csr_path, key_type='ECDSA')
    context.common(['auth', '--csr', csr_path, '--cert-path', cert_path, '--chain-path', chain_path])

    certificate = misc.read_certificate(cert_path)
    assert 'ASN1 OID: secp384r1' in certificate


def test_ocsp_must_staple(context):
    certname = context.wtf('must-staple')
    context.common(['auth', '--must-staple', '--domains', certname])

    certificate = misc.read_certificate(join(context.config_dir,
                                             'live/{0}/cert.pem').format(certname))
    assert 'status_request' in certificate or '1.3.6.1.5.5.7.1.24'


def test_revoke_simple(context):
    certname = context.wtf()
    cert_path = join(context.config_dir, 'live/{0}/cert.pem'.format(certname))
    context.common(['-d', certname])
    context.common(['revoke', '--cert-path', cert_path, '--delete-after-revoke'])

    assert not exists(cert_path)

    certname = context.wtf('le1')
    cert_path = join(context.config_dir, 'live/{0}/cert.pem'.format(certname))
    context.common(['-d', certname])
    context.common(['revoke', '--cert-path', cert_path, '--no-delete-after-revoke'])

    assert exists(cert_path)
    context.common(['delete', '--cert-name', certname])

    assert not exists(join(context.config_dir, 'archive/{0}'.format(certname)))
    assert not exists(join(context.config_dir, 'live/{0}'.format(certname)))
    assert not exists(join(context.config_dir, 'renewal/{0}.conf').format(certname))

    certname = context.wtf('le2')
    key_path = join(context.config_dir, 'live/{0}/privkey.pem'.format(certname))
    cert_path = join(context.config_dir, 'live/{0}/cert.pem'.format(certname))
    context.common(['-d', certname])
    context.common(['revoke', '--cert-path', cert_path, '--key-path', key_path])


def test_revoke_and_unregister(context):
    cert1 = context.wtf('le1')
    cert2 = context.wtf('le2')
    cert3 = context.wtf('le3')

    cert_path1 = join(context.config_dir, 'live/{0}/cert.pem'.format(cert1))
    key_path2 = join(context.config_dir, 'live/{0}/privkey.pem'.format(cert2))
    cert_path2 = join(context.config_dir, 'live/{0}/cert.pem'.format(cert2))

    context.common(['-d', cert1])
    context.common(['-d', cert2])
    context.common(['-d', cert3])

    context.common(['revoke', '--cert-path', cert_path1,
                    '--reason', 'cessationOfOperation'])
    context.common(['revoke', '--cert-path', cert_path2, '--key-path', key_path2,
                    '--reason', 'keyCompromise'])

    context.common(['unregister'])

    output = context.common(['certificates'])

    assert cert1 not in output
    assert cert2 not in output
    assert cert3 in output


def test_revoke_corner_cases(context):
    cert1 = context.wtf('le1')
    context.common(['-d', cert1])
    with pytest.raises(subprocess.CalledProcessError) as error:
        context.common([
            'revoke', '--cert-name', cert1,
            '--cert-path', join(context.config_dir, 'live/{0}/fullchain.pem'.format(cert1))
        ])
        assert 'Exactly one of --cert-path or --cert-name must be specified' in error.out

    assert os.path.isfile(join(context.config_dir, 'renewal/{0}.conf'.format(cert1)))

    cert2 = context.wtf('le2')
    context.common(['-d', cert2])
    with open(join(context.config_dir, 'renewal/{0}.conf'.format(cert2)), 'r') as file:
        data = file.read()

    data = re.sub('archive_dir = .*{0}'.format(os.linesep),
                  'archive_dir = {0}{1}'.format(os.path.normpath(
                      join(context.config_dir, 'archive/{0}'.format(cert1))), os.linesep),
                  data)

    with open(join(context.config_dir, 'renewal/{0}.conf'.format(cert2)), 'w') as file:
        file.write(data)

    output = context.common([
        'revoke', '--cert-path', join(context.config_dir, 'live/{0}/cert.pem'.format(cert1))
    ])

    assert 'Not deleting revoked certs due to overlapping archive dirs' in output


def test_wildcard_certificates(context):
    if context.acme_server == 'boulder-v1':
        pytest.skip('Wildcard certificates are not supported on ACME v1')

    certname = context.wtf('wild')

    context.common([
        '-a', 'manual', '-d', '*.{0},{0}'.format(certname),
        '--preferred-challenge', 'dns',
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook
    ])

    assert exists(join(context.config_dir, 'live/{0}/fullchain.pem'.format(certname)))
