import ssl
import tempfile
import subprocess
import os
import sys

import pytest
from six.moves.urllib.request import urlopen


from certbot_integration_testing.utils import assertions
from certbot_integration_testing.utils.misc import skip_on_pebble, skip_on_pebble_strict


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
        manual_auth_hook = (
            '{0} -c "import os; '
            'challenge_dir = os.path.join(\'{1}\', \'.well-known/acme-challenge\'); '
            'os.makedirs(challenge_dir); '
            'challenge_file = os.path.join(challenge_dir, os.environ.get(\'CERTBOT_TOKEN\')); '
            'open(challenge_file, \'w\').write(os.environ.get(\'CERTBOT_VALIDATION\')); '
            '"'
        ).format(sys.executable, http_01_server)

        manual_cleanup_hook = (
            '{0} -c "import os; import shutil; '
            'well_known = os.path.join(\'{1}\', \'.well-known\'); '
            'shutil.rmtree(well_known); '
            '"'
        ).format(sys.executable, http_01_server)

        certname = 'le.wtf'
        common([
            '-a', 'manual', '-d', certname, '--rsa-key-size', '4096',
            '--cert-name', certname,
            '--manual-auth-hook', manual_auth_hook,
            '--manual-cleanup-hook', manual_cleanup_hook,
            '--pre-hook', 'echo wtf.pre >> "{0}"'.format(hook_probe),
            '--post-hook', 'echo wtf.post >> "{0}"'.format(hook_probe),
            '--renew-hook', 'echo renew >> "{0}"'.format(hook_probe)
        ])

        assertions.assert_hook_execution(hook_probe, 'renew')
        assertions.assert_save_renew_hook(config_dir, certname)
