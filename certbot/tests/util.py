"""Test utilities.

.. warning:: This module is not part of the public API.

"""
import multiprocessing
import os
import pkg_resources
import shutil
import tempfile
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import mock
import OpenSSL
from six.moves import reload_module  # pylint: disable=import-error

from acme import jose

from certbot import constants
from certbot import interfaces
from certbot import storage
from certbot import util

from certbot.display import util as display_util


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


def make_lineage(config_dir, testfile):
    """Creates a lineage defined by testfile.

    This creates the archive, live, and renewal directories if
    necessary and creates a simple lineage.

    :param str config_dir: path to the configuration directory
    :param str testfile: configuration file to base the lineage on

    :returns: path to the renewal conf file for the created lineage
    :rtype: str

    """
    lineage_name = testfile[:-len('.conf')]

    conf_dir = os.path.join(
        config_dir, constants.RENEWAL_CONFIGS_DIR)
    archive_dir = os.path.join(
        config_dir, constants.ARCHIVE_DIR, lineage_name)
    live_dir = os.path.join(
        config_dir, constants.LIVE_DIR, lineage_name)

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

    conf_path = os.path.join(config_dir, conf_dir, testfile)
    with open(vector_path(testfile)) as src:
        with open(conf_path, 'w') as dst:
            dst.writelines(
                line.replace('MAGICDIR', config_dir) for line in src)

    return conf_path


def patch_get_utility(target='zope.component.getUtility'):
    """Patch zope.component.getUtility to use a special mock IDisplay.

    The mock IDisplay works like a regular mock object, except it also
    also asserts that methods are called with valid arguments.

    :param str target: path to patch

    :returns: mock zope.component.getUtility
    :rtype: mock.MagicMock

    """
    return mock.patch(target, new_callable=_create_get_utility_mock)


class FreezableMock(object):
    """Mock object with the ability to freeze attributes.

    This class works like a regular mock.MagicMock object, except
    attributes and behavior can be set and frozen so they cannot be
    changed during tests.

    If a func argument is provided to the constructor, this function
    is called first when an instance of FreezableMock is called,
    followed by the usual behavior defined by MagicMock. The return
    value of func is ignored.

    """
    def __init__(self, frozen=False, func=None):
        self._frozen_set = set() if frozen else set(('freeze',))
        self._func = func
        self._mock = mock.MagicMock()
        self._frozen = frozen

    def freeze(self):
        """Freeze object preventing further changes."""
        self._frozen = True

    def __call__(self, *args, **kwargs):
        if self._func is not None:
            self._func(*args, **kwargs)
        return self._mock(*args, **kwargs)

    def __getattribute__(self, name):
        if name == '_frozen':
            try:
                return object.__getattribute__(self, name)
            except AttributeError:
                return False
        elif name == '_frozen_set' or name in self._frozen_set:
            return object.__getattribute__(self, name)
        else:
            return getattr(object.__getattribute__(self, '_mock'), name)

    def __setattr__(self, name, value):
        if self._frozen:
            return setattr(self._mock, name, value)
        elif name != '_frozen_set':
            self._frozen_set.add(name)
        return object.__setattr__(self, name, value)


def _create_get_utility_mock():
    display = FreezableMock()
    for name in interfaces.IDisplay.names():  # pylint: disable=no-member
        if name != 'notification':
            frozen_mock = FreezableMock(frozen=True, func=_assert_valid_call)
            setattr(display, name, frozen_mock)
    display.freeze()
    return mock.MagicMock(return_value=display)


def _assert_valid_call(*args, **kwargs):
    assert_args = [args[0] if args else kwargs['message']]

    assert_kwargs = {}
    assert_kwargs['default'] = kwargs.get('default', None)
    assert_kwargs['cli_flag'] = kwargs.get('cli_flag', None)
    assert_kwargs['force_interactive'] = kwargs.get('force_interactive', False)

    # pylint: disable=star-args
    display_util.assert_valid_call(*assert_args, **assert_kwargs)


class TempDirTestCase(unittest.TestCase):
    """Base test class which sets up and tears down a temporary directory"""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)


def lock_and_call(func, lock_path):
    """Grab a lock for lock_path and call func.

    :param callable func: object to call after acquiring the lock
    :param str lock_path: path to file or directory to lock

    """
    # Reload module to reset internal _LOCKS dictionary
    reload_module(util)

    # start child and wait for it to grab the lock
    cv = multiprocessing.Condition()
    cv.acquire()
    child_args = (cv, lock_path,)
    child = multiprocessing.Process(target=hold_lock, args=child_args)
    child.start()
    cv.wait()

    # call func and terminate the child
    func()
    cv.notify()
    cv.release()
    child.join()
    assert child.exitcode == 0


def hold_lock(cv, lock_path):  # pragma: no cover
    """Acquire a file lock at lock_path and wait to release it.

    :param multiprocessing.Condition cv: condition for syncronization
    :param str lock_path: path to the file lock

    """
    from certbot import lock
    if os.path.isdir(lock_path):
        my_lock = lock.lock_dir(lock_path)
    else:
        my_lock = lock.LockFile(lock_path)
    cv.acquire()
    cv.notify()
    cv.wait()
    my_lock.release()
