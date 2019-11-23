"""Certbot main public entry point."""
import logging.handlers
import sys

from certbot._internal import main as internal_main


logger = logging.getLogger(__name__)


def main(*args, **kwargs):
    """Shim around internal main function"""
    return internal_main.main(*args, **kwargs)
