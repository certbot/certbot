"""Provides a common base for configurator proxies"""
import logging
import os
import shutil
import tempfile

from certbot import constants
from certbot_compatibility_test import util


logger = logging.getLogger(__name__)


class Proxy(object):
    # pylint: disable=too-many-instance-attributes
    """A common base for compatibility test configurators"""

    @classmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the plugin"""

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        self._temp_dir = tempfile.mkdtemp()
        self.le_config = util.create_le_config(self._temp_dir)
        config_dir = util.extract_configs(args.configs, self._temp_dir)
        self._configs = [
            os.path.join(config_dir, config)
            for config in os.listdir(config_dir)]

        self.args = args
        self.http_port = 80
        self.https_port = 443

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
