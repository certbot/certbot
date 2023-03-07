"""Provides a common base for configurator proxies"""
from abc import abstractmethod
import argparse
import logging
import os
import shutil
import tempfile
from typing import Iterable
from typing import List
from typing import Optional
from typing import overload
from typing import Set
from typing import Tuple
from typing import Type
from typing import Union

from acme import challenges
from acme.challenges import Challenge
from certbot._internal import constants
from certbot.achallenges import AnnotatedChallenge
from certbot.plugins import common
from certbot_compatibility_test import errors
from certbot_compatibility_test import interfaces
from certbot_compatibility_test import util

logger = logging.getLogger(__name__)


class Proxy(interfaces.ConfiguratorProxy):
    """A common base for compatibility test configurators"""

    @classmethod
    def add_parser_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """Adds command line arguments needed by the plugin"""

    def __init__(self, args: argparse.Namespace) -> None:
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
        self._configurator: common.Configurator
        self._all_names: Optional[Set[str]] = None
        self._test_names: Optional[Set[str]] = None

    def has_more_configs(self) -> bool:
        """Returns true if there are more configs to test"""
        return bool(self._configs)

    @abstractmethod
    def cleanup_from_tests(self) -> None:
        """Performs any necessary cleanup from running plugin tests"""

    def load_config(self) -> str:
        """Returns the next config directory to be tested"""
        shutil.rmtree(self.le_config.work_dir, ignore_errors=True)
        backup = os.path.join(self.le_config.work_dir, constants.BACKUP_DIR)
        os.makedirs(backup)
        return self._configs.pop()

    @overload
    def copy_certs_and_keys(self, cert_path: str, key_path: str,
                            chain_path: str) -> Tuple[str, str, str]: ...

    @overload
    def copy_certs_and_keys(self, cert_path: str, key_path: str,
                            chain_path: Optional[str]) -> Tuple[str, str, Optional[str]]: ...

    def copy_certs_and_keys(self, cert_path: str, key_path: str,
                            chain_path: Optional[str] = None) -> Tuple[str, str, Optional[str]]:
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

    def get_all_names_answer(self) -> Set[str]:
        """Returns the set of domain names that the plugin should find"""
        if self._all_names:
            return self._all_names
        raise errors.Error("No configuration file loaded")

    def get_testable_domain_names(self) -> Set[str]:
        """Returns the set of domain names that can be tested against"""
        if self._test_names:
            return self._test_names
        return {"example.com"}

    def deploy_cert(self, domain: str, cert_path: str, key_path: str, chain_path: str,
                    fullchain_path: str) -> None:
        """Installs cert"""
        cert_path, key_path, chain_path = self.copy_certs_and_keys(cert_path, key_path, chain_path)
        if not self._configurator:
            raise ValueError("Configurator plugin is not set.")
        self._configurator.deploy_cert(
            domain, cert_path, key_path, chain_path, fullchain_path)

    def cleanup(self, achalls: List[AnnotatedChallenge]) -> None:
        self._configurator.cleanup(achalls)

    def config_test(self) -> None:
        self._configurator.config_test()

    def enhance(self, domain: str, enhancement: str,
                options: Optional[Union[List[str], str]] = None) -> None:
        self._configurator.enhance(domain, enhancement, options)

    def get_all_names(self) -> Iterable[str]:
        return self._configurator.get_all_names()

    def get_chall_pref(self, domain: str) -> Iterable[Type[Challenge]]:
        return self._configurator.get_chall_pref(domain)

    @classmethod
    def inject_parser_options(cls, parser: argparse.ArgumentParser, name: str) -> None:
        pass

    def more_info(self) -> str:
        return self._configurator.more_info()

    def perform(self, achalls: List[AnnotatedChallenge]) -> List[challenges.ChallengeResponse]:
        return self._configurator.perform(achalls)

    def prepare(self) -> None:
        self._configurator.prepare()

    def recovery_routine(self) -> None:
        self._configurator.recovery_routine()

    def restart(self) -> None:
        self._configurator.restart()

    def rollback_checkpoints(self, rollback: int = 1) -> None:
        self._configurator.rollback_checkpoints(rollback)

    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        self._configurator.save(title, temporary)

    def supported_enhancements(self) -> List[str]:
        return self._configurator.supported_enhancements()
