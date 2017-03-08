"""Utility functions for Certbot plugin tests."""
import argparse
import copy
import os
import re
import shutil
import tarfile

from acme import jose
from acme import test_util
from certbot import constants

from certbot_compatibility_test import errors


_KEY_BASE = "rsa1024_key.pem"
KEY_PATH = test_util.vector_path(_KEY_BASE)
KEY = test_util.load_pyopenssl_private_key(_KEY_BASE)
JWK = jose.JWKRSA(key=test_util.load_rsa_private_key(_KEY_BASE))
IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def create_le_config(parent_dir):
    """Sets up LE dirs in parent_dir and returns the config dict"""
    config = copy.deepcopy(constants.CLI_DEFAULTS)

    le_dir = os.path.join(parent_dir, "certbot")
    config["config_dir"] = os.path.join(le_dir, "config")
    config["work_dir"] = os.path.join(le_dir, "work")
    config["logs_dir"] = os.path.join(le_dir, "logs_dir")
    os.makedirs(config["config_dir"])
    os.mkdir(config["work_dir"])
    os.mkdir(config["logs_dir"])

    config["domains"] = None

    return argparse.Namespace(**config)  # pylint: disable=star-args


def extract_configs(configs, parent_dir):
    """Extracts configs to a new dir under parent_dir and returns it"""
    config_dir = os.path.join(parent_dir, "configs")

    if os.path.isdir(configs):
        shutil.copytree(configs, config_dir, symlinks=True)
    elif tarfile.is_tarfile(configs):
        with tarfile.open(configs, "r") as tar:
            tar.extractall(config_dir)
    else:
        raise errors.Error("Unknown configurations file type")

    return config_dir
