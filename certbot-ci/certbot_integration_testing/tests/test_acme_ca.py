import ssl
import tempfile
import subprocess
import os

import pytest
from six.moves.urllib.request import urlopen


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
        output = common(['plugins', '--init', 'prepare'])

        assert 'webroot' in output
