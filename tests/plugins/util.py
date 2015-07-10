"""Utility functions for Let's Encrypt plugin tests."""
import os
import tarfile
import tempfile


TEMP_DIRECTORY = tempfile.mkdtemp()
# Location of decompressed server root configurations
CONFIGS = os.path.join(TEMP_DIRECTORY, "configs")
SCRIPTS = os.path.join(TEMP_DIRECTORY, "scripts")


def setup_tmp_dir(tar_path):
    """Sets up a temporary directory for this run and returns its path."""
    tar = tarfile.open(tar_path, "r:gz")
    tar.extractall(os.path.join(tmp_dir, SERVER_ROOTS))

    os.makedirs(os.path.join(tmp_dir, "mnt"))
    os.makedirs(os.path.join(tmp_dir, "scripts"))

    return tmp_dir
