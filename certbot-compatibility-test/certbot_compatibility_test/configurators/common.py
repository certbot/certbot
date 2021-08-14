"""Provides a common base for configurator proxies"""
from abc import abstractmethod
import logging
import os
import shutil
import tempfile

from certbot._internal import constants
from certbot_compatibility_test import interfaces
from certbot_compatibility_test import errors
from certbot_compatibility_test import util

logger = logging.getLogger(__name__)


class Proxy(interfaces.ConfiguratorProxy):
    """A common base for compatibility test configurators"""

    @classmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the plugin"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        super().__init__(args)
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
        self._configurator: interfaces.Configurator
        self._all_names = None
        self._test_names = None

    def has_more_configs(self):
        """Returns true if there are more configs to test"""
        return bool(self._configs)

    @abstractmethod
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
        chain = None
        if chain_path:
            chain = os.path.join(cert_and_key_dir, "chain")
            shutil.copy(chain_path, chain)

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
        if not self._configurator:
            raise ValueError("Configurator plugin is not set.")
        self._configurator.deploy_cert(
            domain, cert_path, key_path, chain_path, fullchain_path)


    def cleanup(self, achalls):
        self._configurator.cleanup(achalls)

    def config_test(self):
        self._configurator.config_test()

    def enhance(self, domain, enhancement, options = None):
        self._configurator.enhance(domain, enhancement, options)

    def get_all_names(self):
        return self._configurator.get_all_names()

    def get_chall_pref(self, domain):
        return self._configurator.get_chall_pref(domain)

    @classmethod
    def inject_parser_options(cls, parser, name):
        pass

    def more_info(self):
        return self._configurator.more_info()

    def perform(self, achalls):
        return self._configurator.perform(achalls)

    def prepare(self):
        self._configurator.prepare()

    def recovery_routine(self):
        self._configurator.recovery_routine()

    def restart(self):
        self._configurator.restart()

    def rollback_checkpoints(self, rollback = 1):
        self._configurator.rollback_checkpoints(rollback)

    def save(self, title = None, temporary = False):
        self._configurator.save(title, temporary)

    def supported_enhancements(self):
        return self._configurator.supported_enhancements()
