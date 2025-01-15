"""Module executing integration tests against certbot core."""
import os
from os.path import exists
from os.path import join
import re
import shutil
import subprocess
import time
from typing import Generator
from typing import Tuple
from typing import Type

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
from cryptography.hazmat.primitives.asymmetric.ec import SECP521R1
from cryptography.x509 import NameOID
import pytest

from certbot_integration_tests.certbot_tests.assertions import assert_cert_count_for_lineage
from certbot_integration_tests.certbot_tests.assertions import assert_elliptic_key
from certbot_integration_tests.certbot_tests.assertions import assert_equals_group_owner
from certbot_integration_tests.certbot_tests.assertions import assert_equals_group_permissions
from certbot_integration_tests.certbot_tests.assertions import assert_equals_world_read_permissions
from certbot_integration_tests.certbot_tests.assertions import assert_hook_execution
from certbot_integration_tests.certbot_tests.assertions import assert_rsa_key
from certbot_integration_tests.certbot_tests.assertions import assert_saved_lineage_option
from certbot_integration_tests.certbot_tests.assertions import assert_saved_renew_hook
from certbot_integration_tests.certbot_tests.assertions import assert_world_no_permissions
from certbot_integration_tests.certbot_tests.assertions import assert_world_read_permissions
from certbot_integration_tests.certbot_tests.assertions import EVERYBODY_SID
from certbot_integration_tests.certbot_tests.context import IntegrationTestsContext
from certbot_integration_tests.utils import misc


@pytest.fixture(name='context')
def test_context(request: pytest.FixtureRequest) -> Generator[IntegrationTestsContext, None, None]:
    """Fixture providing the integration test context."""
    # Fixture request is a built-in pytest fixture describing current test request.
    integration_test_context = IntegrationTestsContext(request)
    try:
        yield integration_test_context
    finally:
        integration_test_context.cleanup()


def test_basic_commands(context: IntegrationTestsContext) -> None:
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


def test_hook_dirs_creation(context: IntegrationTestsContext) -> None:
    """Test all hooks directory are created during Certbot startup."""
    context.certbot(['register'])

    for hook_dir in misc.list_renewal_hooks_dirs(context.config_dir):
        assert os.path.isdir(hook_dir)


def test_registration_override(context: IntegrationTestsContext) -> None:
    """Test correct register/unregister, and registration override."""
    context.certbot(['register'])
    context.certbot(['unregister'])
    context.certbot(['register', '--email', 'ex1@domain.org,ex2@domain.org'])

    context.certbot(['update_account', '--email', 'example@domain.org'])
    stdout1, _ = context.certbot(['show_account'])
    context.certbot(['update_account', '--email', 'ex1@domain.org,ex2@domain.org'])
    stdout2, _ = context.certbot(['show_account'])

    assert 'example@domain.org' in stdout1, "New email should be present"
    assert 'example@domain.org' not in stdout2, "Old email should not be present"
    assert 'ex1@domain.org, ex2@domain.org' in stdout2, "New emails should be present"


def test_prepare_plugins(context: IntegrationTestsContext) -> None:
    """Test that plugins are correctly instantiated and displayed."""
    stdout, _ = context.certbot(['plugins', '--init', '--prepare'])

    assert 'webroot' in stdout


def test_http_01(context: IntegrationTestsContext) -> None:
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
    assert_saved_lineage_option(context.config_dir, certname, 'key_type', 'ecdsa')


def test_manual_http_auth(context: IntegrationTestsContext) -> None:
    """Test the HTTP-01 challenge using manual plugin."""
    with misc.create_http_server(context.http_01_port) as webroot,\
            misc.manual_http_hooks(webroot) as scripts:

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


def test_manual_dns_auth(context: IntegrationTestsContext) -> None:
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


def test_certonly(context: IntegrationTestsContext) -> None:
    """Test the certonly verb on certbot."""
    context.certbot(['certonly', '--cert-name', 'newname', '-d', context.get_domain('newname')])

    assert_cert_count_for_lineage(context.config_dir, 'newname', 1)


def test_certonly_webroot(context: IntegrationTestsContext) -> None:
    """Test the certonly verb with webroot plugin"""
    with misc.create_http_server(context.http_01_port) as webroot:
        certname = context.get_domain('webroot')
        context.certbot(['certonly', '-a', 'webroot', '--webroot-path', webroot, '-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)


def test_auth_and_install_with_csr(context: IntegrationTestsContext) -> None:
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


def test_renew_files_permissions(context: IntegrationTestsContext) -> None:
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


def test_renew_with_hook_scripts(context: IntegrationTestsContext) -> None:
    """Test certificate renewal with script hooks."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    assert_hook_execution(context.hook_probe, 'deploy')


def test_renew_files_propagate_permissions(context: IntegrationTestsContext) -> None:
    """Test proper certificate renewal with custom permissions propagated on private key."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    privkey1 = join(context.config_dir, 'archive', certname, 'privkey1.pem')
    privkey2 = join(context.config_dir, 'archive', certname, 'privkey2.pem')

    if os.name != 'nt':
        os.chmod(privkey1, 0o444)
    else:
        import ntsecuritycon  # pylint: disable=import-error
        import win32security  # pylint: disable=import-error

        # Get the current DACL of the private key
        security = win32security.GetFileSecurity(privkey1, win32security.DACL_SECURITY_INFORMATION)
        dacl = security.GetSecurityDescriptorDacl()
        # Create a read permission for Everybody group
        everybody = win32security.ConvertStringSidToSid(EVERYBODY_SID)
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION, ntsecuritycon.FILE_GENERIC_READ, everybody
        )
        # Apply the updated DACL to the private key
        security.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(privkey1, win32security.DACL_SECURITY_INFORMATION, security)

    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    if os.name != 'nt':
        # On Linux, read world permissions + all group permissions
        # will be copied from the previous private key
        assert_world_read_permissions(privkey2)
        assert_equals_world_read_permissions(privkey1, privkey2)
        assert_equals_group_permissions(privkey1, privkey2)
    else:
        # On Windows, world will never have any permissions, and
        # group permission is irrelevant for this platform
        assert_world_no_permissions(privkey2)


def test_graceful_renew_it_is_not_time(context: IntegrationTestsContext) -> None:
    """Test graceful renew is not done when it is not due time."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    context.certbot(['renew', '--deploy-hook', misc.echo('deploy', context.hook_probe)],
                    force_renew=False)

    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')


def test_graceful_renew_it_is_time(context: IntegrationTestsContext) -> None:
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


def test_renew_with_changed_private_key_complexity(context: IntegrationTestsContext) -> None:
    """Test proper renew with updated private key complexity."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname, '--key-type', 'rsa', '--rsa-key-size', '4096'])

    key1 = join(context.config_dir, 'archive', certname, 'privkey1.pem')
    assert_rsa_key(key1, 4096)
    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    key2 = join(context.config_dir, 'archive', certname, 'privkey2.pem')
    assert_rsa_key(key2, 4096)

    context.certbot(['renew', '--rsa-key-size', '2048'])

    key3 = join(context.config_dir, 'archive', certname, 'privkey3.pem')
    assert_rsa_key(key3, 2048)


def test_renew_ignoring_directory_hooks(context: IntegrationTestsContext) -> None:
    """Test hooks are ignored during renewal with relevant CLI flag."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    context.certbot(['renew', '--no-directory-hooks'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    with pytest.raises(AssertionError):
        assert_hook_execution(context.hook_probe, 'deploy')


def test_renew_empty_hook_scripts(context: IntegrationTestsContext) -> None:
    """Test proper renew with empty hook scripts."""
    certname = context.get_domain('renew')
    context.certbot(['-d', certname])

    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    misc.generate_test_file_hooks(context.config_dir, context.hook_probe)
    for hook_dir in misc.list_renewal_hooks_dirs(context.config_dir):
        shutil.rmtree(hook_dir)
        os.makedirs(join(hook_dir, 'dir'))
        with open(join(hook_dir, 'file'), 'w'):
            pass
    context.certbot(['renew'])

    assert_cert_count_for_lineage(context.config_dir, certname, 2)


def test_renew_hook_override(context: IntegrationTestsContext) -> None:
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
    with open(context.hook_probe, 'w'):
        pass
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
    with open(context.hook_probe, 'w'):
        pass
    context.certbot(['renew', '--cert-name', certname])

    assert_hook_execution(context.hook_probe, 'pre_override')
    assert_hook_execution(context.hook_probe, 'post_override')
    assert_hook_execution(context.hook_probe, 'deploy_override')


def test_invalid_domain_with_dns_challenge(context: IntegrationTestsContext) -> None:
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

    stdout, _ = context.certbot(['certificates'])

    assert context.get_domain('fail-dns1') not in stdout


def test_reuse_key(context: IntegrationTestsContext) -> None:
    """Test various scenarios where a key is reused."""
    certname = context.get_domain('reusekey')
    context.certbot(['--domains', certname, '--reuse-key'])
    context.certbot(['renew', '--cert-name', certname])

    with open(join(context.config_dir, 'archive/{0}/privkey1.pem').format(certname), 'r') as file:
        privkey1 = file.read()
    with open(join(context.config_dir, 'archive/{0}/cert1.pem').format(certname), 'r') as file:
        cert1 = file.read()
    with open(join(context.config_dir, 'archive/{0}/privkey2.pem').format(certname), 'r') as file:
        privkey2 = file.read()
    with open(join(context.config_dir, 'archive/{0}/cert2.pem').format(certname), 'r') as file:
        cert2 = file.read()
    assert privkey1 == privkey2

    context.certbot(['--cert-name', certname, '--domains', certname, '--force-renewal'])

    with open(join(context.config_dir, 'archive/{0}/privkey3.pem').format(certname), 'r') as file:
        privkey3 = file.read()
    with open(join(context.config_dir, 'archive/{0}/cert3.pem').format(certname), 'r') as file:
        cert3 = file.read()
    assert privkey2 != privkey3

    context.certbot(['--cert-name', certname, '--domains', certname,
                     '--reuse-key','--force-renewal'])
    with open(join(context.config_dir, 'archive/{0}/privkey4.pem').format(certname), 'r') as file:
        privkey4 = file.read()
    context.certbot(['renew', '--cert-name', certname, '--no-reuse-key', '--force-renewal'])
    with open(join(context.config_dir, 'archive/{0}/privkey5.pem').format(certname), 'r') as file:
        privkey5 = file.read()
    context.certbot(['renew', '--cert-name', certname, '--force-renewal'])
    with open(join(context.config_dir, 'archive/{0}/privkey6.pem').format(certname), 'r') as file:
        privkey6 = file.read()

    assert privkey3 == privkey4
    assert privkey4 != privkey5
    assert privkey5 != privkey6

    assert len({cert1, cert2, cert3}) == 3


def test_reuse_key_allow_subset_of_names(context: IntegrationTestsContext) -> None:
    """Test that key is reused when allow_subset_of_names is set."""
    certname = context.get_domain('dns1')
    domains = ','.join([certname, context.get_domain('fail-dns1')])
    context.certbot([
        '-a', 'manual', '-d', domains,
        '--allow-subset-of-names',
        '--preferred-challenges', 'dns',
        '--manual-auth-hook', context.manual_dns_auth_hook_allow_fail,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook,
        '--reuse-key'
    ])

    stdout, _ = context.certbot(['certificates'])
    assert context.get_domain('fail-dns1') in stdout
    certname = context.get_domain('dns1')
    with open(join(context.config_dir, 'archive/{0}/privkey1.pem').format(certname), 'r') as file:
        privkey1 = file.read()

    # manual_dns_auth_hook from misc is designed to fail if the domain contains 'fail-*'.
    context.certbot([
        'reconfigure',
        '--cert-name', certname,
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '-a', 'manual' # needed to override --standalone passed automatically
    ])

    context.certbot(['renew', '--cert-name', certname, '--force-renewal', '-a', 'manual'])
    stdout, _ = context.certbot(['certificates'])
    assert context.get_domain('fail-dns1') not in stdout

    with open(join(context.config_dir, 'archive/{0}/privkey1.pem').format(certname), 'r') as file:
        privkey1 = file.read()
    with open(join(context.config_dir, 'archive/{0}/privkey2.pem').format(certname), 'r') as file:
        privkey2 = file.read()
    assert privkey1 == privkey2


def test_new_key(context: IntegrationTestsContext) -> None:
    """Tests --new-key and its interactions with --reuse-key"""
    def private_key(generation: int) -> Tuple[str, str]:
        pk_path = join(context.config_dir, f'archive/{certname}/privkey{generation}.pem')
        with open(pk_path, 'r') as file:
            return file.read(), pk_path

    certname = context.get_domain('newkey')

    context.certbot(['--domains', certname, '--reuse-key',
                     '--key-type', 'ecdsa', '--elliptic-curve', 'secp384r1'])
    privkey1, _ = private_key(1)

    # renew: --new-key should replace the key, but keep reuse_key and the key type + params
    context.certbot(['renew', '--cert-name', certname, '--new-key'])
    privkey2, privkey2_path = private_key(2)
    assert privkey1 != privkey2
    assert_saved_lineage_option(context.config_dir, certname, 'reuse_key', 'True')
    assert_elliptic_key(privkey2_path, SECP384R1)

    # certonly: it should replace the key but the elliptic curve will change
    context.certbot(['certonly', '-d', certname, '--reuse-key', '--new-key'])
    privkey3, privkey3_path = private_key(3)
    assert privkey2 != privkey3
    assert_saved_lineage_option(context.config_dir, certname, 'reuse_key', 'True')
    assert_elliptic_key(privkey3_path, SECP256R1)

    # certonly: it should be possible to change the key type and keep reuse_key
    context.certbot(['certonly', '-d', certname, '--reuse-key', '--new-key', '--key-type', 'rsa',
                     '--rsa-key-size', '4096', '--cert-name', certname])
    privkey4, privkey4_path = private_key(4)
    assert privkey3 != privkey4
    assert_saved_lineage_option(context.config_dir, certname, 'reuse_key', 'True')
    assert_rsa_key(privkey4_path, 4096)

    # certonly: it should not be possible to change a key parameter without --new-key
    with pytest.raises(subprocess.CalledProcessError) as error:
        context.certbot(['certonly', '-d', certname, '--key-type', 'rsa', '--reuse-key',
                         '--rsa-key-size', '2048'])
    assert 'Unable to change the --rsa-key-size' in error.value.stderr

    # certonly: not specifying --key-type should keep the existing key type (non-interactively).
    context.certbot(['certonly', '-d', certname, '--no-reuse-key'])
    privkey5, privkey5_path = private_key(5)
    assert_rsa_key(privkey5_path, 2048)
    assert privkey4 != privkey5


def test_incorrect_key_type(context: IntegrationTestsContext) -> None:
    with pytest.raises(subprocess.CalledProcessError):
        context.certbot(['--key-type="failwhale"'])


def test_ecdsa(context: IntegrationTestsContext) -> None:
    """Test issuance for ECDSA CSR based request (legacy supported mode)."""
    key_path = join(context.workspace, 'privkey-p384.pem')
    csr_path = join(context.workspace, 'csr-p384.der')
    cert_path = join(context.workspace, 'cert-p384.pem')
    chain_path = join(context.workspace, 'chain-p384.pem')

    misc.generate_csr(
        [context.get_domain('ecdsa')],
        key_path, csr_path,
        key_type=misc.ECDSA_KEY_TYPE
    )
    context.certbot([
        'auth', '--csr', csr_path, '--cert-path', cert_path,
        '--chain-path', chain_path,
    ])

    certificate = misc.read_certificate(cert_path)
    assert 'ASN1 OID: secp384r1' in certificate


def test_default_key_type(context: IntegrationTestsContext) -> None:
    """Test default key type is ECDSA"""
    certname = context.get_domain('renew')
    context.certbot([
        'certonly',
        '--cert-name', certname, '-d', certname
    ])
    filename = join(context.config_dir, 'archive/{0}/privkey1.pem').format(certname)
    assert_elliptic_key(filename, SECP256R1)


def test_default_rsa_size(context: IntegrationTestsContext) -> None:
    """test that the RSA key size used when not specifying any is 2048"""
    certname = context.get_domain('renew')
    context.certbot([
        '--key-type', 'rsa', '--cert-name', certname, '-d', certname
    ])
    key1 = join(context.config_dir, 'archive/{0}/privkey1.pem'.format(certname))
    assert_rsa_key(key1, 2048)


@pytest.mark.parametrize('curve,curve_cls', [
    # Curve name, Curve class, ACME servers to skip
    ('secp256r1', SECP256R1),
    ('secp384r1', SECP384R1),
    ('secp521r1', SECP521R1)]
)
def test_ecdsa_curves(context: IntegrationTestsContext, curve: str,
                      curve_cls: Type[EllipticCurve]) -> None:
    """Test issuance for each supported ECDSA curve"""
    domain = context.get_domain('curve')
    context.certbot([
        'certonly',
        '--key-type', 'ecdsa', '--elliptic-curve', curve,
        '--force-renewal', '-d', domain,
    ])
    key = join(context.config_dir, "live", domain, 'privkey.pem')
    assert_elliptic_key(key, curve_cls)


def test_renew_with_ec_keys(context: IntegrationTestsContext) -> None:
    """Test proper renew with updated private key complexity."""
    certname = context.get_domain('renew')
    context.certbot([
        'certonly',
        '--cert-name', certname,
        '--key-type', 'ecdsa', '--elliptic-curve', 'secp256r1',
        '--force-renewal', '-d', certname,
    ])
    key1 = join(context.config_dir, "archive", certname, 'privkey1.pem')
    assert 200 < os.stat(key1).st_size < 250  # ec keys of 256 bits are ~225 bytes
    assert_elliptic_key(key1, SECP256R1)
    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    assert_saved_lineage_option(context.config_dir, certname, 'key_type', 'ecdsa')

    context.certbot(['renew', '--elliptic-curve', 'secp384r1'])
    assert_cert_count_for_lineage(context.config_dir, certname, 2)
    key2 = join(context.config_dir, 'archive', certname, 'privkey2.pem')
    assert 280 < os.stat(key2).st_size < 320  # ec keys of 384 bits are ~310 bytes
    assert_elliptic_key(key2, SECP384R1)

    # When running non-interactively, if --key-type is unspecified but the default value differs
    # to the lineage key type, Certbot should keep the lineage key type. The curve will still
    # change to the default value, in order to stay consistent with the behavior of certonly.
    context.certbot(['certonly', '--force-renewal', '-d', certname])
    key3 = join(context.config_dir, 'archive', certname, 'privkey3.pem')
    assert 200 < os.stat(key3).st_size < 250  # ec keys of 256 bits are ~225 bytes
    assert_elliptic_key(key3, SECP256R1)

    # When running non-interactively, specifying a different --key-type requires user confirmation
    # with both --key-type and --cert-name.
    with pytest.raises(subprocess.CalledProcessError) as error:
        context.certbot(['certonly', '--force-renewal', '-d', certname,
                         '--key-type', 'rsa'])
    assert 'Please provide both --cert-name and --key-type' in error.value.stderr

    context.certbot(['certonly', '--force-renewal', '-d', certname,
                     '--key-type', 'rsa', '--cert-name', certname])
    key4 = join(context.config_dir, 'archive', certname, 'privkey4.pem')
    assert_rsa_key(key4)

    # We expect that the previous behavior of requiring both --cert-name and
    # --key-type to be set to not apply to the renew subcommand.
    context.certbot(['renew', '--force-renewal', '--key-type', 'ecdsa'])
    key5 = join(context.config_dir, 'archive', certname, 'privkey5.pem')
    assert 200 < os.stat(key5).st_size < 250  # ec keys of 256 bits are ~225 bytes
    assert_elliptic_key(key5, SECP256R1)


def test_ocsp_must_staple(context: IntegrationTestsContext) -> None:
    """Test that OCSP Must-Staple is correctly set in the generated certificate."""
    certname = context.get_domain('must-staple')
    context.certbot(['auth', '--must-staple', '--domains', certname])

    certificate = misc.read_certificate(join(context.config_dir,
                                             'live/{0}/cert.pem').format(certname))
    assert 'status_request' in certificate or '1.3.6.1.5.5.7.1.24' in certificate


def test_revoke_simple(context: IntegrationTestsContext) -> None:
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


def test_revoke_and_unregister(context: IntegrationTestsContext) -> None:
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

    stdout, _ = context.certbot(['certificates'])

    assert cert1 not in stdout
    assert cert2 not in stdout
    assert cert3 in stdout


@pytest.mark.parametrize('curve,curve_cls', [
    ('secp256r1', SECP256R1),
    ('secp384r1', SECP384R1),
    ('secp521r1', SECP521R1)]
)
def test_revoke_ecdsa_cert_key(
    context: IntegrationTestsContext, curve: str, curve_cls: Type[EllipticCurve]) -> None:
    """Test revoking a certificate """
    cert: str = context.get_domain('curve')
    context.certbot([
        'certonly',
        '--key-type', 'ecdsa', '--elliptic-curve', curve,
        '-d', cert,
    ])
    key = join(context.config_dir, "live", cert, 'privkey.pem')
    cert_path = join(context.config_dir, "live", cert, 'cert.pem')
    assert_elliptic_key(key, curve_cls)
    context.certbot([
        'revoke', '--cert-path', cert_path, '--key-path', key,
        '--no-delete-after-revoke',
    ])
    stdout, _ = context.certbot(['certificates'])
    assert stdout.count('INVALID: REVOKED') == 1, 'Expected {0} to be REVOKED'.format(cert)


@pytest.mark.parametrize('curve,curve_cls', [
    ('secp256r1', SECP256R1),
    ('secp384r1', SECP384R1),
    ('secp521r1', SECP521R1)]
)
def test_revoke_ecdsa_cert_key_delete(
    context: IntegrationTestsContext, curve: str, curve_cls: Type[EllipticCurve]) -> None:
    """Test revoke and deletion for each supported curve type"""
    cert: str = context.get_domain('curve')
    context.certbot([
        'certonly',
        '--key-type', 'ecdsa', '--elliptic-curve', curve,
        '-d', cert,
    ])
    key = join(context.config_dir, "live", cert, 'privkey.pem')
    cert_path = join(context.config_dir, "live", cert, 'cert.pem')
    assert_elliptic_key(key, curve_cls)
    context.certbot([
        'revoke', '--cert-path', cert_path, '--key-path', key,
        '--delete-after-revoke',
    ])
    assert not exists(cert_path)


def test_revoke_mutual_exclusive_flags(context: IntegrationTestsContext) -> None:
    """Test --cert-path and --cert-name cannot be used during revoke."""
    cert = context.get_domain('le1')
    context.certbot(['-d', cert])
    with pytest.raises(subprocess.CalledProcessError) as error:
        context.certbot([
            'revoke', '--cert-name', cert,
            '--cert-path', join(context.config_dir, 'live', cert, 'fullchain.pem')
        ])
    assert 'Exactly one of --cert-path or --cert-name must be specified' in error.value.stderr


def test_revoke_multiple_lineages(context: IntegrationTestsContext) -> None:
    """Test revoke does not delete certs if multiple lineages share the same dir."""
    cert1 = context.get_domain('le1')
    context.certbot(['-d', cert1])

    assert os.path.isfile(join(context.config_dir, 'renewal', '{0}.conf'.format(cert1)))

    cert2 = context.get_domain('le2')
    context.certbot(['-d', cert2])

    # Copy over renewal configuration of cert1 into renewal configuration of cert2.
    with open(join(context.config_dir, 'renewal', '{0}.conf'.format(cert2)), 'r') as file:
        data = file.read()

    data = re.sub(
        'archive_dir = .*\n',
        'archive_dir = {0}\n'.format(
            join(context.config_dir, 'archive', cert1).replace('\\', '\\\\')
        ), data
    )

    with open(join(context.config_dir, 'renewal', '{0}.conf'.format(cert2)), 'w') as file:
        file.write(data)

    context.certbot([
        'revoke', '--cert-path', join(context.config_dir, 'live', cert1, 'cert.pem')
    ])

    with open(join(context.workspace, 'logs', 'letsencrypt.log'), 'r') as f:
        assert 'Not deleting revoked certificates due to overlapping archive dirs' in f.read()


def test_reconfigure(context: IntegrationTestsContext) -> None:
    """Test the reconfigure verb"""
    certname = context.get_domain()
    context.certbot(['-d', certname])
    conf_path = join(context.config_dir, 'renewal', '{}.conf'.format(certname))

    with misc.create_http_server(context.http_01_port) as webroot:
        context.certbot(['reconfigure', '--cert-name', certname,
                         '-a', 'webroot', '--webroot-path', webroot])
        with open(conf_path, 'r') as f:
            file_contents = f.read()
            # Check changed value
            assert 'authenticator = webroot' in file_contents, \
                   'Expected authenticator to be changed to webroot in renewal config'
            # Check added value
            assert f'webroot_path = {webroot}' in file_contents, \
                   'Expected new webroot path to be added to renewal config'


def test_wildcard_certificates(context: IntegrationTestsContext) -> None:
    """Test wildcard certificate issuance."""
    certname = context.get_domain('wild')

    context.certbot([
        '-a', 'manual', '-d', '*.{0},{0}'.format(certname),
        '--preferred-challenge', 'dns',
        '--manual-auth-hook', context.manual_dns_auth_hook,
        '--manual-cleanup-hook', context.manual_dns_cleanup_hook
    ])

    assert exists(join(context.config_dir, 'live', certname, 'fullchain.pem'))


def test_ocsp_status_stale(context: IntegrationTestsContext) -> None:
    """Test retrieval of OCSP statuses for staled config"""
    sample_data_path = misc.load_sample_data_path(context.workspace)
    stdout, _ = context.certbot(['certificates', '--config-dir', sample_data_path])

    assert stdout.count('TEST_CERT') == 2, ('Did not find two test certs as expected ({0})'
                                            .format(stdout.count('TEST_CERT')))
    assert stdout.count('EXPIRED') == 2, ('Did not find two expired certs as expected ({0})'
                                          .format(stdout.count('EXPIRED')))


def test_ocsp_status_live(context: IntegrationTestsContext) -> None:
    """Test retrieval of OCSP statuses for live config"""
    cert = context.get_domain('ocsp-check')

    # OSCP 1: Check live certificate OCSP status (VALID)
    context.certbot(['--domains', cert])
    stdout, _ = context.certbot(['certificates'])

    assert stdout.count('VALID') == 1, 'Expected {0} to be VALID'.format(cert)
    assert stdout.count('EXPIRED') == 0, 'Did not expect {0} to be EXPIRED'.format(cert)

    # OSCP 2: Check live certificate OCSP status (REVOKED)
    context.certbot(['revoke', '--cert-name', cert, '--no-delete-after-revoke'])
    # Sometimes in oldest tests (using openssl binary and not cryptography), the OCSP status is
    # not seen immediately by Certbot as invalid. Waiting few seconds solves this transient issue.
    time.sleep(5)
    stdout, _ = context.certbot(['certificates'])

    assert stdout.count('INVALID') == 1, 'Expected {0} to be INVALID'.format(cert)
    assert stdout.count('REVOKED') == 1, 'Expected {0} to be REVOKED'.format(cert)


def test_ocsp_renew(context: IntegrationTestsContext) -> None:
    """Test that revoked certificates are renewed."""
    # Obtain a certificate
    certname = context.get_domain('ocsp-renew')
    context.certbot(['--domains', certname])

    # Test that "certbot renew" does not renew the certificate
    assert_cert_count_for_lineage(context.config_dir, certname, 1)
    context.certbot(['renew'], force_renew=False)
    assert_cert_count_for_lineage(context.config_dir, certname, 1)

    # Revoke the certificate and test that it does renew the certificate
    context.certbot(['revoke', '--cert-name', certname, '--no-delete-after-revoke'])
    context.certbot(['renew'], force_renew=False)
    assert_cert_count_for_lineage(context.config_dir, certname, 2)


def test_dry_run_deactivate_authzs(context: IntegrationTestsContext) -> None:
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


def test_preferred_chain(context: IntegrationTestsContext) -> None:
    """Test that --preferred-chain results in the correct chain.pem being produced"""
    try:
        issuers = misc.get_acme_issuers()
    except NotImplementedError:
        pytest.skip('This ACME server does not support alternative issuers.')

    names = [str(i.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value) \
             for i in issuers]

    domain = context.get_domain('preferred-chain')
    cert_path = join(context.config_dir, 'live', domain, 'chain.pem')
    conf_path = join(context.config_dir, 'renewal', '{}.conf'.format(domain))

    for (requested, expected) in [(n, n) for n in names] + [('nonexistent', names[0])]:
        args = ['certonly', '--cert-name', domain, '-d', domain,
                '--preferred-chain', requested, '--force-renewal']
        context.certbot(args)

        dumped = misc.read_certificate(cert_path)
        assert f'Issuer: CN={expected}'in dumped, \
               f'Expected chain issuer to be {expected} when preferring {requested}'

        with open(conf_path, 'r') as f:
            assert f'preferred_chain = {requested}' in f.read(), \
                   'Expected preferred_chain to be set in renewal config'


def test_ancient_rsa_key_type_preserved(context: IntegrationTestsContext) -> None:
    certname = context.get_domain('newname')
    context.certbot(['certonly', '-d', certname, '--key-type', 'rsa'])
    assert_saved_lineage_option(context.config_dir, certname, 'key_type', 'rsa')

    # Remove `key_type = rsa` from the renewal config to emulate a <v1.25.0 Certbot certificate.
    conf_path = join(context.config_dir, 'renewal', f'{certname}.conf')
    conf_contents: str = ''
    with open(conf_path) as f:
        conf_contents = f.read()
    conf_contents = conf_contents.replace('key_type = rsa', '')
    with open(conf_path, 'w') as f:
        f.write(conf_contents)

    context.certbot(['renew', '--cert-name', certname, '--force-renewal'])

    assert_saved_lineage_option(context.config_dir, certname, 'key_type', 'rsa')
    key2 = join(context.config_dir, 'archive/{0}/privkey2.pem'.format(certname))
    assert_rsa_key(key2, 2048)
