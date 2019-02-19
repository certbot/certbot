"""Test utilities.

.. warning:: This module is not part of the public API.

"""
import multiprocessing
import os
import pkg_resources
import shutil
import tempfile
import unittest
import sys
import warnings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import mock
import OpenSSL
import josepy as jose
import six
from six.moves import reload_module  # pylint: disable=import-error

from certbot import constants
from certbot import interfaces
from certbot import storage
from certbot import util
from certbot import configuration

from certbot.display import util as display_util


def vector_path(*names):
    """Path to a test vector."""
    return pkg_resources.resource_filename(
        __name__, os.path.join('testdata', *names))


def load_vector(*names):
    """Load contents of a test vector."""
    # luckily, resource_string opens file in binary mode
    data = pkg_resources.resource_string(
        __name__, os.path.join('testdata', *names))
    # Try at most to convert CRLF to LF when data is text
    try:
        return data.decode().replace('\r\n', '\n').encode()
    except ValueError:
        # Failed to process the file with standard encoding.
        # Most likely not a text file, return its bytes untouched.
        return data


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


def patch_get_utility_with_stdout(target='zope.component.getUtility',
                                  stdout=None):
    """Patch zope.component.getUtility to use a special mock IDisplay.

    The mock IDisplay works like a regular mock object, except it also
    also asserts that methods are called with valid arguments.

    The `message` argument passed to the IDisplay methods is passed to
    stdout's write method.

    :param str target: path to patch
    :param object stdout: object to write standard output to; it is
        expected to have a `write` method

    :returns: mock zope.component.getUtility
    :rtype: mock.MagicMock

    """
    stdout = stdout if stdout else six.StringIO()

    freezable_mock = _create_get_utility_mock_with_stdout(stdout)
    return mock.patch(target, new=freezable_mock)


class FreezableMock(object):
    """Mock object with the ability to freeze attributes.

    This class works like a regular mock.MagicMock object, except
    attributes and behavior set before the object is frozen cannot
    be changed during tests.

    If a func argument is provided to the constructor, this function
    is called first when an instance of FreezableMock is called,
    followed by the usual behavior defined by MagicMock. The return
    value of func is ignored.

    """
    def __init__(self, frozen=False, func=None, return_value=mock.sentinel.DEFAULT):
        self._frozen_set = set() if frozen else set(('freeze',))
        self._func = func
        self._mock = mock.MagicMock()
        if return_value != mock.sentinel.DEFAULT:
            self.return_value = return_value
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
        elif name in ('return_value', 'side_effect',):
            return getattr(object.__getattribute__(self, '_mock'), name)
        elif name == '_frozen_set' or name in self._frozen_set:
            return object.__getattribute__(self, name)
        else:
            return getattr(object.__getattribute__(self, '_mock'), name)

    def __setattr__(self, name, value):
        """ Before it is frozen, attributes are set on the FreezableMock
        instance and added to the _frozen_set. Attributes in the _frozen_set
        cannot be changed after the FreezableMock is frozen. In this case,
        they are set on the underlying _mock.

        In cases of return_value and side_effect, these attributes are always
        passed through to the instance's _mock and added to the _frozen_set
        before the object is frozen.

        """
        if self._frozen:
            if name in self._frozen_set:
                raise AttributeError('Cannot change frozen attribute ' + name)
            else:
                return setattr(self._mock, name, value)

        if name != '_frozen_set':
            self._frozen_set.add(name)

        if name in ('return_value', 'side_effect'):
            return setattr(self._mock, name, value)

        else:
            return object.__setattr__(self, name, value)


def _create_get_utility_mock():
    display = FreezableMock()
    for name in interfaces.IDisplay.names():  # pylint: disable=no-member
        if name != 'notification':
            frozen_mock = FreezableMock(frozen=True, func=_assert_valid_call)
            setattr(display, name, frozen_mock)
    display.freeze()
    return FreezableMock(frozen=True, return_value=display)


def _create_get_utility_mock_with_stdout(stdout):
    def _write_msg(message, *unused_args, **unused_kwargs):
        """Write to message to stdout.
        """
        if message:
            stdout.write(message)

    def mock_method(*args, **kwargs):
        """
        Mock function for IDisplay methods.
        """
        _assert_valid_call(args, kwargs)
        _write_msg(*args, **kwargs)


    display = FreezableMock()
    for name in interfaces.IDisplay.names():  # pylint: disable=no-member
        if name == 'notification':
            frozen_mock = FreezableMock(frozen=True,
                                        func=_write_msg)
            setattr(display, name, frozen_mock)
        else:
            frozen_mock = FreezableMock(frozen=True,
                                        func=mock_method)
            setattr(display, name, frozen_mock)
    display.freeze()

    return FreezableMock(frozen=True, return_value=display)


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
        """Execute before test"""
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        """Execute after test"""
        # On Windows we have various files which are not correctly closed at the time of tearDown.
        # For know, we log them until a proper file close handling is written.
        # Useful for development only, so no warning when we are on a CI process.
        def onerror_handler(_, path, excinfo):
            """On error handler"""
            if not os.environ.get('APPVEYOR'): # pragma: no cover
                message = ('Following error occurred when deleting the tempdir {0}'
                           ' for path {1} during tearDown process: {2}'
                           .format(self.tempdir, path, str(excinfo)))
                warnings.warn(message)
        shutil.rmtree(self.tempdir, onerror=onerror_handler)

class ConfigTestCase(TempDirTestCase):
    """Test class which sets up a NamespaceConfig object.

    """
    def setUp(self):
        super(ConfigTestCase, self).setUp()
        self.config = configuration.NamespaceConfig(
            mock.MagicMock(**constants.CLI_DEFAULTS)
        )
        self.config.verb = "certonly"
        self.config.config_dir = os.path.join(self.tempdir, 'config')
        self.config.work_dir = os.path.join(self.tempdir, 'work')
        self.config.logs_dir = os.path.join(self.tempdir, 'logs')
        self.config.cert_path = constants.CLI_DEFAULTS['auth_cert_path']
        self.config.fullchain_path = constants.CLI_DEFAULTS['auth_chain_path']
        self.config.chain_path = constants.CLI_DEFAULTS['auth_chain_path']
        self.config.server = "https://example.com"

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

    :param multiprocessing.Condition cv: condition for synchronization
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

def skip_on_windows(reason):
    """Decorator to skip permanently a test on Windows. A reason is required."""
    def wrapper(function):
        """Wrapped version"""
        return unittest.skipIf(sys.platform == 'win32', reason)(function)
    return wrapper

def broken_on_windows(function):
    """Decorator to skip temporarily a broken test on Windows."""
    reason = 'Test is broken and ignored on windows but should be fixed.'
    return unittest.skipIf(
        sys.platform == 'win32'
        and os.environ.get('SKIP_BROKEN_TESTS_ON_WINDOWS', 'true') == 'true',
        reason)(function)

def temp_join(path):
    """
    Return the given path joined to the tempdir path for the current platform
    Eg.: 'cert' => /tmp/cert (Linux) or 'C:\\Users\\currentuser\\AppData\\Temp\\cert' (Windows)
    """
    return  os.path.join(tempfile.gettempdir(), path)
