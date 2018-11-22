import ssl
import tempfile
import subprocess
import os

import pytest
from six.moves.urllib.request import urlopen


from certbot_integration_testing.utils import assertions
from certbot_integration_testing.utils.misc import skip_on_pebble

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

    @skip_on_pebble('TLS-SNI-01 challenges are deprecated, and so not supported by Pebble')
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
