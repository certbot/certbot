"""Utility functions for Certbot plugin tests."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import ipaddress
import os
import re
import shutil
import tarfile
from typing import Optional
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import types
import josepy as jose

from certbot._internal import constants
from certbot.tests import util as test_util
from certbot_compatibility_test import errors

_KEY_BASE = "rsa2048_key.pem"
KEY_PATH = test_util.vector_path(_KEY_BASE)
KEY = test_util.load_rsa_private_key_pem(_KEY_BASE)
JWK = jose.JWKRSA(key=test_util.load_jose_rsa_private_key_pem(_KEY_BASE))
IP_REGEX = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def create_le_config(parent_dir: str) -> argparse.Namespace:
    """Sets up LE dirs in parent_dir and returns the config dict"""
    config = copy.deepcopy(constants.CLI_DEFAULTS)

    le_dir = os.path.join(parent_dir, "certbot")
    os.mkdir(le_dir)
    for dir_name in ("config", "logs", "work"):
        full_path = os.path.join(le_dir, dir_name)
        os.mkdir(full_path)
        full_name = dir_name + "_dir"
        config[full_name] = full_path

    config["domains"] = None

    return argparse.Namespace(**config)


def extract_configs(configs: str, parent_dir: str) -> str:
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


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def make_self_signed_cert(private_key: types.CertificateIssuerPrivateKeyTypes,
                          domains: Optional[list[str]] = None,
                          not_before: Optional[datetime] = None,
                          validity: Optional[timedelta] = None, force_san: bool = True,
                          extensions: Optional[list[x509.Extension]] = None,
                          ips: Optional[list[Union[ipaddress.IPv4Address,
                                                   ipaddress.IPv6Address]]] = None
                          ) -> x509.Certificate:
    """Generate new self-signed certificate.
    :param buffer private_key_pem: Private key, in PEM PKCS#8 format.
    :type domains: `list` of `str`
    :param int not_before: A datetime after which the cert is valid. If no
    timezone is specified, UTC is assumed
    :type not_before: `datetime.datetime`
    :param validity: Duration for which the cert will be valid. Defaults to 1
    week
    :type validity: `datetime.timedelta`
    :param buffer private_key_pem: One of
    `cryptography.hazmat.primitives.asymmetric.types.CertificateIssuerPrivateKeyTypes`
    :param bool force_san:
    :param extensions: List of additional extensions to include in the cert.
    :type extensions: `list` of `x509.Extension[x509.ExtensionType]`
    :type ips: `list` of (`ipaddress.IPv4Address` or `ipaddress.IPv6Address`)
    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.
    """
    assert domains or ips, "Must provide one or more hostnames or IPs for the cert."

    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())

    if extensions is not None:
        for ext in extensions:
            builder = builder.add_extension(ext.value, ext.critical)
    if domains is None:
        domains = []
    if ips is None:
        ips = []
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)

    name_attrs = []
    if len(domains) > 0:
        name_attrs.append(x509.NameAttribute(
            x509.OID_COMMON_NAME,
            domains[0]
        ))

    builder = builder.subject_name(x509.Name(name_attrs))
    builder = builder.issuer_name(x509.Name(name_attrs))

    sanlist: list[x509.GeneralName] = []
    for address in domains:
        sanlist.append(x509.DNSName(address))
    for ip in ips:
        sanlist.append(x509.IPAddress(ip))
    if force_san or len(domains) > 1 or len(ips) > 0:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sanlist),
            critical=False
        )

    if not_before is None:
        not_before = _now()
    if validity is None:
        validity = timedelta(seconds=7 * 24 * 60 * 60)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_before + validity)

    public_key = private_key.public_key()
    builder = builder.public_key(public_key)
    return builder.sign(private_key, hashes.SHA256())
