"""Certbot main public entry point."""
import logging.handlers
import sys

from certbot._internal import main as internal_main


logger = logging.getLogger(__name__)


def main(*args, **kwargs):
    """Shim around internal main function"""
    return internal_main.main(*args, **kwargs)


if __name__ == "__main__":
    err_string = main()
    if err_string:
        logger.warning("Exiting with message %s", err_string)
    sys.exit(err_string)  # pragma: no cover
