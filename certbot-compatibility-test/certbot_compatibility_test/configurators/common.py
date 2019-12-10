"""Provides a common base for configurator proxies"""
import logging
import os
import shutil
import tempfile

from certbot._internal import constants
from certbot_compatibility_test import errors
from certbot_compatibility_test import util

logger = logging.getLogger(__name__)


class Proxy(object):
    """A common base for compatibility test configurators"""

    @classmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the plugin"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        self._temp_dir = tempfile.mkdtemp()
        # tempfile.mkdtemp() creates folders with too restrictive permissions to be accessible
        # to an Apache worker, leading to HTTP challenge failures. Let's fix that.
        os.chmod(self._temp_dir, 0o755)
        self.le_config = util.create_le_config(self._temp_dir)
        config_dir = util.extract_configs(args.configs, self._temp_dir)
        self._configs = [
            os.path.join(config_dir, config)
            for config in os.listdir(config_dir)]

        self.args = args
        self.http_port = 80
        self.https_port = 443
        self._configurator = self._all_names = self._test_names = None

    def __getattr__(self, name):
        """Wraps the configurator methods"""
        if self._configurator is None:
            raise AttributeError()

        method = getattr(self._configurator, name, None)
        if callable(method):
            return method
        raise AttributeError()

    def has_more_configs(self):
        """Returns true if there are more configs to test"""
        return bool(self._configs)

    def cleanup_from_tests(self):
        """Performs any necessary cleanup from running plugin tests"""

    def load_config(self):
        """Returns the next config directory to be tested"""
        shutil.rmtree(self.le_config.work_dir, ignore_errors=True)
        backup = os.path.join(self.le_config.work_dir, constants.BACKUP_DIR)
        os.makedirs(backup)
        return self._configs.pop()

    def copy_certs_and_keys(self, cert_path, key_path, chain_path=None):
        """Copies certs and keys into the temporary directory"""
        cert_and_key_dir = os.path.join(self._temp_dir, "certs_and_keys")
        if not os.path.isdir(cert_and_key_dir):
            os.mkdir(cert_and_key_dir)

        cert = os.path.join(cert_and_key_dir, "cert")
        shutil.copy(cert_path, cert)
        key = os.path.join(cert_and_key_dir, "key")
        shutil.copy(key_path, key)
        if chain_path:
            chain = os.path.join(cert_and_key_dir, "chain")
            shutil.copy(chain_path, chain)
        else:
            chain = None

        return cert, key, chain

    def get_all_names_answer(self):
        """Returns the set of domain names that the plugin should find"""
        if self._all_names:
            return self._all_names
        raise errors.Error("No configuration file loaded")

    def get_testable_domain_names(self):
        """Returns the set of domain names that can be tested against"""
        if self._test_names:
            return self._test_names
        return {"example.com"}

    def deploy_cert(self, domain, cert_path, key_path, chain_path=None,
                    fullchain_path=None):
        """Installs cert"""
        cert_path, key_path, chain_path = self.copy_certs_and_keys(
            cert_path, key_path, chain_path)
        self._configurator.deploy_cert(
            domain, cert_path, key_path, chain_path, fullchain_path)
