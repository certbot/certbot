import ssl
import tempfile
import subprocess
import os

import pytest
from six.moves.urllib.request import urlopen

from certbot_integration_tests.utils import assertions
from certbot_integration_tests.utils import misc
from certbot_integration_tests.utils.misc import skip_on_pebble, skip_on_pebble_strict, generate_csr


@pytest.mark.incremental
class TestSuite(object):

    def test_directory_accessibility(self, acme_url):
        context = ssl.SSLContext()
        urlopen(acme_url, context=context)

    def test_basic_commands(self, common):
        initial_count_tmpfiles = len(os.listdir(tempfile.tempdir))

        with pytest.raises(subprocess.CalledProcessError):
            common(['--csr'])
        common(['--help'])
        common(['--help', 'all'])
        common(['--version'])

        new_count_tmpfiles = len(os.listdir(tempfile.tempdir))
        assert initial_count_tmpfiles == new_count_tmpfiles

    def test_hook_dirs_creation(self, common, renewal_hooks_dirs):
        common(['register'])

        for hook_dir in renewal_hooks_dirs:
            assert os.path.isdir(hook_dir)

    def test_registration_override(self, common):
        common(['unregister'])
        common(['register', '--email', 'ex1@domain.org,ex2@domain.org'])
        common(['register', '--update-registration', '--email', 'ex1@domain.org'])
        common(['register', '--update-registration', '--email', 'ex1@domain.org,ex2@domain.org'])

    def test_prepare_plugins(self, common):
        output = common(['plugins', '--init', '--prepare'])

        assert 'webroot' in output

    @skip_on_pebble('TLS-SNI-01 challenges are deprecated, and so are not supported by Pebble')
    def test_tls_sni_01(self, common, config_dir, hook_probe, http_01_server):
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
    def test_http_01(self, common, config_dir, hook_probe, tls_sni_01_server):
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

    def test_manual_http_auth(self, common, hook_probe, http_01_server, config_dir):
        certname = 'le.wtf'
        common([
            'certonly', '-a', 'manual', '-d', certname, '--rsa-key-size', '4096',
            '--cert-name', certname,
            '--manual-auth-hook', misc.generate_manual_http_auth_hook(http_01_server),
            '--manual-cleanup-hook', misc.generate_manual_http_cleanup_hook(http_01_server),
            '--pre-hook', 'echo wtf.pre >> "{0}"'.format(hook_probe),
            '--post-hook', 'echo wtf.post >> "{0}"'.format(hook_probe),
            '--renew-hook', 'echo renew >> "{0}"'.format(hook_probe)
        ])

        with pytest.raises(AssertionError):
            assertions.assert_hook_execution(hook_probe, 'renew')
        assertions.assert_save_renew_hook(config_dir, certname)

    def test_manual_dns_auth(self, common, hook_probe, config_dir):
        certname = 'dns.le.wtf'
        common([
            '-a', 'manual', '-d', certname, '--preferred-challenges', 'dns,tls-sni',
            'run', '--cert-name', certname,
            '--manual-auth-hook', misc.generate_manual_dns_auth_hook(),
            '--manual-cleanup-hook', misc.generate_manual_dns_cleanup_hook(),
            '--pre-hook', 'echo wtf.pre >> "{0}"'.format(hook_probe),
            '--post-hook', 'echo wtf.post >> "{0}"'.format(hook_probe),
            '--renew-hook', 'echo renew >> "{0}"'.format(hook_probe)
        ])

        with pytest.raises(AssertionError):
            assertions.assert_hook_execution(hook_probe, 'renew')
        assertions.assert_save_renew_hook(config_dir, certname)

    def test_certonly(self, common):
        common(['certonly', '--cert-name', 'newname', '-d', 'newname.le.wtf'])

    def test_auth_and_install_with_csr(self, workspace, common):
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

        misc.print_certificate(cert_path)
        misc.print_certificate(chain_path)

        common([
            '--domains', 'le3.wtf', 'install',
            '--cert-path', cert_path,
            '--key-path', key_path
        ])

    # def test_renew(self, config_dir, common_no_force_renew, common):
    #     certificate = 'le.wtf'
    #     assertions.assert_certs_count_for_lineage(config_dir, certificate, 1)
    #
    #     common_no_force_renew(['renew'])
    #     assertions.assert_certs_count_for_lineage(config_dir, certificate, 1)
    #
    #     common(['renew', '--cert-name', certificate, '--authenticator', 'manual'])
    #     assertions.assert_certs_count_for_lineage(config_dir, certificate, 2)
