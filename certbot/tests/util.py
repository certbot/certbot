"""Test utilities.

.. warning:: This module is not part of the public API.

"""
import os
import pkg_resources
import shutil
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import OpenSSL

from acme import errors
from acme import jose
from acme import util

from certbot import constants
from certbot import storage


def vector_path(*names):
    """Path to a test vector."""
    return pkg_resources.resource_filename(
        __name__, os.path.join('testdata', *names))


def load_vector(*names):
    """Load contents of a test vector."""
    # luckily, resource_string opens file in binary mode
    return pkg_resources.resource_string(
        __name__, os.path.join('testdata', *names))


def _guess_loader(filename, loader_pem, loader_der):
    _, ext = os.path.splitext(filename)
    if ext.lower() == '.pem':
        return loader_pem
    elif ext.lower() == '.der':
        return loader_der
    else:  # pragma: no cover
        raise ValueError("Loader could not be recognized based on extension")


def load_cert(*names):
    """Load certificate."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_certificate(loader, load_vector(*names))


def load_comparable_cert(*names):
    """Load ComparableX509 cert."""
    return jose.ComparableX509(load_cert(*names))


def load_csr(*names):
    """Load certificate request."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_certificate_request(loader, load_vector(*names))


def load_comparable_csr(*names):
    """Load ComparableX509 certificate request."""
    return jose.ComparableX509(load_csr(*names))


def load_rsa_private_key(*names):
    """Load RSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return jose.ComparableRSAKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_pyopenssl_private_key(*names):
    """Load pyOpenSSL private key."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_privatekey(loader, load_vector(*names))


def requirement_available(requirement):
    """Checks if requirement can be imported.

    :rtype: bool
    :returns: ``True`` iff requirement can be imported

    """
    try:
        util.activate(requirement)
    except errors.DependencyError:  # pragma: no cover
        return False
    return True  # pragma: no cover


def skip_unless(condition, reason):  # pragma: no cover
    """Skip tests unless a condition holds.

    This implements the basic functionality of unittest.skipUnless
    which is only available on Python 2.7+.

    :param bool condition: If ``False``, the test will be skipped
    :param str reason: the reason for skipping the test

    :rtype: callable
    :returns: decorator that hides tests unless condition is ``True``

    """
    if hasattr(unittest, "skipUnless"):
        return unittest.skipUnless(condition, reason)
    elif condition:
        return lambda cls: cls
    else:
        return lambda cls: None


def make_lineage(self, testfile):
    """Creates a lineage defined by testfile.

    This creates the archive, live, and renewal directories if
    necessary and creates a simple lineage.

    :param str testfile: configuration file to base the lineage on

    :returns: path to the renewal conf file for the created lineage
    :rtype: str

    """
    lineage_name = testfile[:-len('.conf')]

    conf_dir = os.path.join(
        self.config_dir, constants.RENEWAL_CONFIGS_DIR)
    archive_dir = os.path.join(
        self.config_dir, constants.ARCHIVE_DIR, lineage_name)
    live_dir = os.path.join(
        self.config_dir, constants.LIVE_DIR, lineage_name)

    for directory in (archive_dir, conf_dir, live_dir,):
        if not os.path.exists(directory):
            os.makedirs(directory)

    sample_archive = vector_path('sample-archive')
    for kind in os.listdir(sample_archive):
        shutil.copyfile(os.path.join(sample_archive, kind),
                        os.path.join(archive_dir, kind))

    for kind in storage.ALL_FOUR:
        os.symlink(os.path.join(archive_dir, '{0}1.pem'.format(kind)),
                   os.path.join(live_dir, '{0}.pem'.format(kind)))

    conf_path = os.path.join(self.config_dir, conf_dir, testfile)
    with open(vector_path(testfile)) as src:
        with open(conf_path, 'w') as dst:
            dst.writelines(
                line.replace('MAGICDIR', self.config_dir) for line in src)

    return conf_path
