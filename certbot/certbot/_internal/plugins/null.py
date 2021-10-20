"""Null plugin."""
import logging
from typing import Callable
from typing import List
from typing import Optional

from certbot import interfaces
from certbot.plugins import common

logger = logging.getLogger(__name__)


class Installer(common.Plugin, interfaces.Installer):
    """Null installer."""

    description = "Null Installer"
    hidden = True

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        pass

    # pylint: disable=missing-function-docstring

    def prepare(self) -> None:
        pass  # pragma: no cover

    def more_info(self) -> str:
        return "Installer that doesn't do anything (for testing)."

    def get_all_names(self) -> List[str]:
        return []

    def deploy_cert(self, domain: str, cert_path: str, key_path: str,
                    chain_path: str, fullchain_path: str) -> None:
        pass  # pragma: no cover

    def enhance(self, domain: str, enhancement: str,
                options: Optional[List[str]] = None) -> None:
        pass  # pragma: no cover

    def supported_enhancements(self) -> List[str]:
        return []

    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        pass  # pragma: no cover

    def rollback_checkpoints(self, rollback: int = 1) -> None:
        pass  # pragma: no cover

    def recovery_routine(self) -> None:
        pass  # pragma: no cover

    def config_test(self) -> None:
        pass  # pragma: no cover

    def restart(self) -> None:
        pass  # pragma: no cover
