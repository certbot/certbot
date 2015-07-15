"""Utility functions for Let's Encrypt plugin tests."""
import contextlib
import os
import shutil
import socket
import tarfile
import tempfile

from tests.compatibility import errors


# Paths used in the program relative to the temp directory
CONFIG_DIR = "configs"
LE_CONFIG = os.path.join("letsencrypt", "config")
LE_LOGS = os.path.join("letsencrypt", "logs")


def setup_temp_dir(configs):
    """Sets up a temporary directory and extracts server configs"""
    temp_dir = tempfile.mkdtemp()
    config_dir = os.path.join(temp_dir, CONFIG_DIR)

    if os.path.isdir(configs):
        shutil.copytree(configs, config_dir, symlinks=True)
    elif tarfile.is_tarfile(configs):
        with tarfile.open(configs, 'r') as tar:
            tar.extractall(config_dir)
    else:
        raise errors.Error('Unknown configurations file type')

    return temp_dir


def get_two_free_ports():
    """Returns two free ports to use for the tests"""
    with contextlib.closing(socket.socket()) as sock1:
        with contextlib.closing(socket.socket()) as sock2:
            sock1.bind(('', 0))
            sock2.bind(('', 0))

            return sock1.getsockname()[1], sock2.getsockname()[1]
