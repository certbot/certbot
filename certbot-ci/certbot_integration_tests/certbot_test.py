from __future__ import print_function
import tempfile
import subprocess
import shutil
import os
import re

import pytest

from certbot_integration_tests.utils import assertions
from certbot_integration_tests.utils import misc
from certbot_integration_tests.utils.markers import (
    skip_on_pebble, skip_on_pebble_strict, skip_on_boulder_v1
)


def test_basic_commands(common):
    initial_count_tmpfiles = len(os.listdir(tempfile.tempdir))

    common(['--help'])
    common(['--help', 'all'])
    common(['--version'])

    with pytest.raises(misc.CertbotSystemExitError):
        common(['--csr'])

    new_count_tmpfiles = len(os.listdir(tempfile.tempdir))
    #assert initial_count_tmpfiles == new_count_tmpfiles


def test_hook_dirs_creation(common, config_dir):
    common(['register'])

    for hook_dir in misc.list_renewal_hooks_dirs(config_dir):
        assert os.path.isdir(hook_dir)


def test_registration_override(common):
    common(['register'])
    common(['unregister'])
    common(['register', '--email', 'ex1@domain.org,ex2@domain.org'])
    common(['register', '--update-registration', '--email', 'ex1@domain.org'])
    common(['register', '--update-registration', '--email', 'ex1@domain.org,ex2@domain.org'])


def test_prepare_plugins(common, capsys):
    output = common(['plugins', '--init', '--prepare'])

    assert 'webroot' in output


@skip_on_pebble('TLS-SNI-01 challenges are deprecated, and so are not supported by Pebble')
def test_tls_sni_01(common, config_dir, hook_probe, http_01_server):
    assert http_01_server

    certname = 'le1.wtf'
    common([
        '--domains', certname, '--preferred-challenges', 'tls-sni-01', 'run',
        '--cert-name', certname,
        '--pre-hook', 'echo wtf.pre >> "{0}"'.format(hook_probe),
        '--post-hook', 'echo wtf.post >> "{0}"'.format(hook_probe),
        '--deploy-hook', 'echo deploy >> "{0}"'.format(hook_probe)
    ])

    assertions.assert_hook_execution(hook_probe, 'deploy')
    assertions.assert_save_renew_hook(config_dir, certname)


@skip_on_pebble_strict('HTTP-01 challenges use useless keyAuthorization keys,'
                       'and so are not supported by Pebble with strict mode.')
def test_http_01(common, config_dir, hook_probe, tls_sni_01_server):
    assert tls_sni_01_server

    certname = 'le2.wtf'
    common([
        '--domains', certname, '--preferred-challenges', 'http-01', 'run',
        '--cert-name', certname,
        '--pre-hook', 'echo wtf.pre >> "{0}"'.format(hook_probe),
        '--post-hook', 'echo wtf.post >> "{0}"'.format(hook_probe),
        '--deploy-hook', 'echo deploy >> "{0}"'.format(hook_probe)
    ])

    assertions.assert_hook_execution(hook_probe, 'deploy')
    assertions.assert_save_renew_hook(config_dir, certname)


def test_manual_http_auth(common, hook_probe, config_dir,
                          manual_http_auth_hook, manual_http_cleanup_hook):
    certname = 'le.wtf'
    common([
        'certonly', '-a', 'manual', '-d', certname,
        '--cert-name', certname,
        '--manual-auth-hook', manual_http_auth_hook,
        '--manual-cleanup-hook', manual_http_cleanup_hook,
        '--pre-hook', 'echo wtf.pre >> "{0}"'.format(hook_probe),
        '--post-hook', 'echo wtf.post >> "{0}"'.format(hook_probe),
        '--renew-hook', 'echo renew >> "{0}"'.format(hook_probe)
    ])

    with pytest.raises(AssertionError):
        assertions.assert_hook_execution(hook_probe, 'renew')
    assertions.assert_save_renew_hook(config_dir, certname)


def test_manual_dns_auth(common, hook_probe, config_dir,
                         manual_dns_auth_hook, manual_dns_cleanup_hook):
    certname = 'dns.le.wtf'
    common([
        '-a', 'manual', '-d', certname, '--preferred-challenges', 'dns,tls-sni',
        'run', '--cert-name', certname,
        '--manual-auth-hook', manual_dns_auth_hook,
        '--manual-cleanup-hook', manual_dns_cleanup_hook,
        '--pre-hook', 'echo wtf.pre >> "{0}"'.format(hook_probe),
        '--post-hook', 'echo wtf.post >> "{0}"'.format(hook_probe),
        '--renew-hook', 'echo renew >> "{0}"'.format(hook_probe)
    ])

    with pytest.raises(AssertionError):
        assertions.assert_hook_execution(hook_probe, 'renew')
    assertions.assert_save_renew_hook(config_dir, certname)


def test_certonly(common):
    common(['certonly', '--cert-name', 'newname', '-d', 'newname.le.wtf'])


def test_auth_and_install_with_csr(workspace, common):
    key_path = os.path.join(workspace, 'key.pem')
    csr_path = os.path.join(workspace, 'csr.der')

    misc.generate_csr(['le3.wtf'], key_path, csr_path)

    cert_path = os.path.join(workspace, 'csr/cert.pem')
    chain_path = os.path.join(workspace, 'csr/chain.pem')

    common([
        'auth', '--csr', csr_path,
        '--cert-path', cert_path,
        '--chain-path', chain_path
    ])

    print(misc.read_certificate(cert_path))
    print(misc.read_certificate(chain_path))

    common([
        '--domains', 'le3.wtf', 'install',
        '--cert-path', cert_path,
        '--key-path', key_path
    ])


def test_renew(config_dir, common_no_force_renew, common, hook_probe):
    # First, we create a target certificate, with all hook dirs instantiated.
    # We should have a new certificate, with hooks executed.
    certname = 'renew.le.wtf'
    common([
        'certonly', '-d', certname, '--rsa-key-size', '4096',
        '--preferred-challenges', 'http-01'
    ])

    assertions.assert_certs_count_for_lineage(config_dir, certname, 1)

    # Second, we force renew, and ensure that renewal hooks files are executed.
    misc.generate_test_file_hooks(config_dir, hook_probe)
    common(['renew', '--no-renew-time-shuffle'])

    assertions.assert_certs_count_for_lineage(config_dir, certname, 2)
    assertions.assert_hook_execution(hook_probe, 'deploy')

    # Third, we try to renew without force.
    # It is not time, so no renew should occur, and no hooks should be executed.
    open(hook_probe, 'w').close()
    misc.generate_test_file_hooks(config_dir, hook_probe)
    common_no_force_renew(['renew', '--no-renew-time-shuffle'])

    assertions.assert_certs_count_for_lineage(config_dir, certname, 2)
    with pytest.raises(AssertionError):
        assertions.assert_hook_execution(hook_probe, 'deploy')

    # Fourth, we modify the time when renew occur to 4 years before expiration.
    # When trying renew without force, then renew should occur for this large time.
    # Also we specify to not use hooks dir, so no hook should be run during this renew.
    # Finally, this renew will use explicitly a 2048 key size.
    open(hook_probe, 'w').close()
    with open(os.path.join(config_dir, 'renewal/{0}.conf'.format(certname)), 'r') as file:
        lines = file.readlines()
    lines.insert(4, 'renew_before_expiry = 100 years{0}'.format(os.linesep))
    with open(os.path.join(config_dir, 'renewal/{0}.conf'.format(certname)), 'w') as file:
        file.writelines(lines)
    common_no_force_renew(['renew', '--no-renew-time-shuffle', '--no-directory-hooks',
                           '--rsa-key-size', '2048'])

    assertions.assert_certs_count_for_lineage(config_dir, certname, 3)
    with pytest.raises(AssertionError):
        assertions.assert_hook_execution(hook_probe, 'deploy')
    key2 = os.path.join(config_dir, 'archive/{0}/privkey2.pem'.format(certname))
    key3 = os.path.join(config_dir, 'archive/{0}/privkey3.pem'.format(certname))
    assert os.stat(key2).st_size > 3000  # 4096 bits keys takes more than 3000 bytes
    assert os.stat(key3).st_size < 1800  # 2048 bits keys takes less than 1800 bytes

    # Fifth, we clean every dir hook, and replace their content by empty dir and empty files.
    # Everything should renew correctly.
    for hook_dir in misc.list_renewal_hooks_dirs(config_dir):
        shutil.rmtree(hook_dir)
        os.makedirs(os.path.join(hook_dir, 'dir'))
        open(os.path.join(hook_dir, 'file'), 'w').close()
    common(['renew', '--no-renew-time-shuffle'])

    assertions.assert_certs_count_for_lineage(config_dir, certname, 4)


def test_hook_override(common, hook_probe):
    certname = 'override.le.wtf'
    common([
        'certonly', '-d', certname,
        '--preferred-challenges', 'http-01',
        '--pre-hook', 'echo pre >> "{0}"'.format(hook_probe),
        '--post-hook', 'echo post >> "{0}"'.format(hook_probe),
        '--deploy-hook', 'echo deploy >> "{0}"'.format(hook_probe)
    ])

    assertions.assert_hook_execution(hook_probe, 'pre')
    assertions.assert_hook_execution(hook_probe, 'post')
    assertions.assert_hook_execution(hook_probe, 'deploy')

    open(hook_probe, 'w').close()
    common([
        'renew', '--cert-name', certname, '--no-renew-time-shuffle',
        '--pre-hook', 'echo pre-override >> "{0}"'.format(hook_probe),
        '--post-hook', 'echo post-override >> "{0}"'.format(hook_probe),
        '--deploy-hook', 'echo deploy-override >> "{0}"'.format(hook_probe)
    ])

    assertions.assert_hook_execution(hook_probe, 'pre-override')
    assertions.assert_hook_execution(hook_probe, 'post-override')
    assertions.assert_hook_execution(hook_probe, 'deploy-override')
    with pytest.raises(AssertionError):
        assertions.assert_hook_execution(hook_probe, 'pre')
    with pytest.raises(AssertionError):
        assertions.assert_hook_execution(hook_probe, 'post')
    with pytest.raises(AssertionError):
        assertions.assert_hook_execution(hook_probe, 'deploy')

    open(hook_probe, 'w').close()
    common([
        'renew', '--cert-name', certname, '--no-renew-time-shuffle'
    ])

    assertions.assert_hook_execution(hook_probe, 'pre-override')
    assertions.assert_hook_execution(hook_probe, 'post-override')
    assertions.assert_hook_execution(hook_probe, 'deploy-override')


def test_invalid_domain_with_dns_challenge(common, manual_dns_auth_hook, manual_dns_cleanup_hook):
    common([
        '-a', 'manual', '-d', 'dns1.le.wtf,fail.dns1.le.wtf',
        '--allow-subset-of-names',
        '--preferred-challenges', 'dns,tls-sni',
        '--manual-auth-hook', manual_dns_auth_hook,
        '--manual-cleanup-hook', manual_dns_cleanup_hook
    ])

    output = common(['certificates'])

    assert 'fail.dns1.le.wtf' not in output


def test_reuse_key(common, config_dir):
    certname = 'reusekey.le.wtf'
    common(['--domains', certname, '--reuse-key'])
    common(['renew', '--cert-name', certname, '--no-renew-time-shuffle'])

    with open(os.path.join(config_dir, 'archive/{0}/privkey1.pem').format(certname), 'r') as file:
        privkey1 = file.read()
    with open(os.path.join(config_dir, 'archive/{0}/privkey2.pem').format(certname), 'r') as file:
        privkey2 = file.read()
    assert privkey1 == privkey2

    common(['--cert-name', certname, '--no-renew-time-shuffle',
            '--domains', certname, '--force-renewal'])

    with open(os.path.join(config_dir, 'archive/{0}/privkey3.pem').format(certname), 'r') as file:
        privkey3 = file.read()
    assert privkey2 != privkey3

    with open(os.path.join(config_dir, 'archive/{0}/cert1.pem').format(certname), 'r') as file:
        cert1 = file.read()
    with open(os.path.join(config_dir, 'archive/{0}/cert2.pem').format(certname), 'r') as file:
        cert2 = file.read()
    with open(os.path.join(config_dir, 'archive/{0}/cert3.pem').format(certname), 'r') as file:
        cert3 = file.read()

    assert len({cert1, cert2, cert3}) == 3


def test_ecdsa(common, workspace):
    key_path = os.path.join(workspace, 'privkey-p384.pem')
    csr_path = os.path.join(workspace, 'csr-p384.der')
    cert_path = os.path.join(workspace, 'cert-p384.pem')
    chain_path = os.path.join(workspace, 'chain-p384.pem')

    misc.generate_csr(['ecdsa.le.wtf'], key_path, csr_path, key_type='ECDSA')

    common(['auth', '--csr', csr_path, '--cert-path', cert_path, '--chain-path', chain_path])

    certificate = misc.read_certificate(cert_path)
    assert 'ASN1 OID: secp384r1' in certificate


def test_ocsp_must_staple(common, config_dir):
    common(['auth', '--must-staple', '--domains', 'must-staple.le.wtf'])

    certificate = misc.read_certificate(os.path.join(config_dir, 'live/must-staple.le.wtf/cert.pem'))
    assert 'status_request' in certificate or '1.3.6.1.5.5.7.1.24'


def test_revoke_simple(common, config_dir):
    cert_path = os.path.join(config_dir, 'live/le.wtf/cert.pem')
    common(['-d', 'le.wtf'])
    common(['revoke', '--cert-path', cert_path, '--delete-after-revoke'])

    assert not os.path.exists(cert_path)

    cert_path = os.path.join(config_dir, 'live/le1.wtf/cert.pem')
    common(['-d', 'le1.wtf'])
    common(['revoke', '--cert-path', cert_path, '--no-delete-after-revoke'])

    assert os.path.exists(cert_path)

    common(['delete', '--cert-name', 'le1.wtf'])

    assert not os.path.exists(os.path.join(config_dir, 'archive/le1.wtf'))
    assert not os.path.exists(os.path.join(config_dir, 'live/le1.wtf'))
    assert not os.path.exists(os.path.join(config_dir, 'renewal/le1.wtf.conf'))

    key_path = os.path.join(config_dir, 'live/le2.wtf/privkey.pem')
    cert_path = os.path.join(config_dir, 'live/le2.wtf/cert.pem')
    common(['-d', 'le2.wtf'])
    common(['revoke', '--cert-path', cert_path, '--key-path', key_path])


def test_revoke_and_unregister(common, config_dir):
    cert_path1 = os.path.join(config_dir, 'live/le1.wtf/cert.pem')
    key_path2 = os.path.join(config_dir, 'live/le2.wtf/privkey.pem')
    cert_path2 = os.path.join(config_dir, 'live/le2.wtf/cert.pem')

    common(['-d', 'le1.wtf'])
    common(['-d', 'le2.wtf'])
    common(['-d', 'le3.wtf'])

    common(['revoke', '--cert-path', cert_path1,
            '--reason', 'cessationOfOperation'])
    common(['revoke', '--cert-path', cert_path2, '--key-path', key_path2,
            '--reason', 'keyCompromise'])

    common(['unregister'])

    output = common(['certificates'])

    assert 'le1.wtf' not in output
    assert 'le2.wtf' not in output
    assert 'le3.wtf' in output


def test_revoke_corner_cases(common, config_dir):
    common(['-d', 'le1.wtf'])
    with pytest.raises(misc.CertbotSystemExitError) as error:
        common([
            'revoke', '--cert-name', 'le.wtf'
            '--cert-path', os.path.join(config_dir, 'live/le1.wtf/fullchain.pem')
        ])
        assert 'Exactly one of --cert-path or --cert-name must be specified' in error.out

    assert os.path.isfile(os.path.join(config_dir, 'renewal/le1.wtf.conf'))

    common(['-d', 'le2.wtf'])
    with open(os.path.join(config_dir, 'renewal/le2.wtf.conf'), 'r') as file:
        data = file.read()

    data = re.sub('archive_dir = .*{0}'.format(os.linesep),
                  'archive_dir = {0}{1}'.format(os.path.normpath(
                      os.path.join(config_dir, 'archive/le1.wtf')), os.linesep),
                  data)

    with open(os.path.join(config_dir, 'renewal/le2.wtf.conf'), 'w') as file:
        file.write(data)

    output = common([
        'revoke', '--cert-path', os.path.join(config_dir, 'live/le1.wtf/cert.pem')
    ])

    assert 'Not deleting revoked certs due to overlapping archive dirs' in output


@skip_on_boulder_v1('Wildcard certificates are not supported on ACME v1')
def test_wildcard_certificates(common, config_dir, manual_dns_auth_hook, manual_dns_cleanup_hook):
    common([
        '-a', 'manual', '-d', '*.wild.le.wtf,wild.le.wtf',
        '--preferred-challenge', 'dns',
        '--manual-auth-hook', manual_dns_auth_hook,
        '--manual-cleanup-hook', manual_dns_cleanup_hook
    ])

    assert os.path.exists(os.path.join(config_dir, 'live/wild.le.wtf/fullchain.pem'))
