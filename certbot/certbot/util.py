"""Utilities for all Certbot."""
# distutils.version under virtualenv confuses pylint
# For more info, see: https://github.com/PyCQA/pylint/issues/73
import argparse
import atexit
import collections
from collections import OrderedDict
import distutils.version
import errno
import logging
import platform
import re
import socket
import subprocess
import sys

import configargparse
import six

from acme.magic_typing import Tuple
from acme.magic_typing import Union
from certbot import errors
from certbot._internal import constants
from certbot._internal import lock
from certbot.compat import filesystem
from certbot.compat import os

_USE_DISTRO = sys.platform.startswith('linux')
if _USE_DISTRO:
    import distro

logger = logging.getLogger(__name__)


Key = collections.namedtuple("Key", "file pem")
# Note: form is the type of data, "pem" or "der"
CSR = collections.namedtuple("CSR", "file data form")


# ANSI SGR escape codes
# Formats text as bold or with increased intensity
ANSI_SGR_BOLD = '\033[1m'
# Colors text red
ANSI_SGR_RED = "\033[31m"
# Resets output format
ANSI_SGR_RESET = "\033[0m"


PERM_ERR_FMT = os.linesep.join((
    "The following error was encountered:", "{0}",
    "Either run as root, or set --config-dir, "
    "--work-dir, and --logs-dir to writeable paths."))


# Stores importing process ID to be used by atexit_register()
_INITIAL_PID = os.getpid()
# Maps paths to locked directories to their lock object. All locks in
# the dict are attempted to be cleaned up at program exit. If the
# program exits before the lock is cleaned up, it is automatically
# released, but the file isn't deleted.
_LOCKS = OrderedDict() # type: OrderedDict[str, lock.LockFile]


def env_no_snap_for_external_calls():
    """
    When Certbot is run inside a Snap, certain environment variables
    are modified. But Certbot sometimes calls out to external programs,
    since it uses classic confinement. When we do that, we must modify
    the env to remove our modifications so it will use the system's
    libraries, since they may be incompatible with the versions of
    libraries included in the Snap. For example, apachectl, Nginx, and
    anything run from inside a hook should call this function and pass
    the results into the ``env`` argument of ``subprocess.Popen``.

    :returns: A modified copy of os.environ ready to pass to Popen
    :rtype: dict

    """
    env = os.environ.copy()
    # Avoid accidentally modifying env
    if 'SNAP' not in env or 'CERTBOT_SNAPPED' not in env:
        return env
    for path_name in ('PATH', 'LD_LIBRARY_PATH'):
        if path_name in env:
            env[path_name] = ':'.join(x for x in env[path_name].split(':') if env['SNAP'] not in x)
    return env


def run_script(params, log=logger.error):
    """Run the script with the given params.

    :param list params: List of parameters to pass to Popen
    :param callable log: Logger method to use for errors

    """
    try:
        proc = subprocess.Popen(params,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                env=env_no_snap_for_external_calls())

    except (OSError, ValueError):
        msg = "Unable to run the command: %s" % " ".join(params)
        log(msg)
        raise errors.SubprocessError(msg)

    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        msg = "Error while running %s.\n%s\n%s" % (
            " ".join(params), stdout, stderr)
        # Enter recovery routine...
        log(msg)
        raise errors.SubprocessError(msg)

    return stdout, stderr


def exe_exists(exe):
    """Determine whether path/name refers to an executable.

    :param str exe: Executable path or name

    :returns: If exe is a valid executable
    :rtype: bool

    """
    path, _ = os.path.split(exe)
    if path:
        return filesystem.is_executable(exe)
    for path in os.environ["PATH"].split(os.pathsep):
        if filesystem.is_executable(os.path.join(path, exe)):
            return True

    return False


def lock_dir_until_exit(dir_path):
    """Lock the directory at dir_path until program exit.

    :param str dir_path: path to directory

    :raises errors.LockError: if the lock is held by another process

    """
    if not _LOCKS:  # this is the first lock to be released at exit
        atexit_register(_release_locks)

    if dir_path not in _LOCKS:
        _LOCKS[dir_path] = lock.lock_dir(dir_path)


def _release_locks():
    for dir_lock in six.itervalues(_LOCKS):
        try:
            dir_lock.release()
        except:  # pylint: disable=bare-except
            msg = 'Exception occurred releasing lock: {0!r}'.format(dir_lock)
            logger.debug(msg, exc_info=True)
    _LOCKS.clear()


def set_up_core_dir(directory, mode, strict):
    """Ensure directory exists with proper permissions and is locked.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param bool strict: require directory to be owned by current user

    :raises .errors.LockError: if the directory cannot be locked
    :raises .errors.Error: if the directory cannot be made or verified

    """
    try:
        make_or_verify_dir(directory, mode, strict)
        lock_dir_until_exit(directory)
    except OSError as error:
        logger.debug("Exception was:", exc_info=True)
        raise errors.Error(PERM_ERR_FMT.format(error))


def make_or_verify_dir(directory, mode=0o755, strict=False):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param bool strict: require directory to be owned by current user

    :raises .errors.Error: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        filesystem.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if strict and not filesystem.check_permissions(directory, mode):
                raise errors.Error(
                    "%s exists, but it should be owned by current user with"
                    " permissions %s" % (directory, oct(mode)))
        else:
            raise


def safe_open(path, mode="w", chmod=None):
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `filesystem.open`, uses Python defaults
        if ``None``.

    """
    open_args = ()  # type: Union[Tuple[()], Tuple[int]]
    if chmod is not None:
        open_args = (chmod,)
    fdopen_args = ()  # type: Union[Tuple[()], Tuple[int]]
    fd = filesystem.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, *open_args)
    return os.fdopen(fd, mode, *fdopen_args)


def _unique_file(path, filename_pat, count, chmod, mode):
    while True:
        current_path = os.path.join(path, filename_pat(count))
        try:
            return safe_open(current_path, chmod=chmod, mode=mode),\
                os.path.abspath(current_path)
        except OSError as err:
            # "File exists," is okay, try a different name.
            if err.errno != errno.EEXIST:
                raise
        count += 1


def unique_file(path, chmod=0o777, mode="w"):
    """Safely finds a unique file.

    :param str path: path/filename.ext
    :param int chmod: File mode
    :param str mode: Open mode

    :returns: tuple of file object and file name

    """
    path, tail = os.path.split(path)
    return _unique_file(
        path, filename_pat=(lambda count: "%04d_%s" % (count, tail)),
        count=0, chmod=chmod, mode=mode)


def unique_lineage_name(path, filename, chmod=0o644, mode="w"):
    """Safely finds a unique file using lineage convention.

    :param str path: directory path
    :param str filename: proposed filename
    :param int chmod: file mode
    :param str mode: open mode

    :returns: tuple of file object and file name (which may be modified
        from the requested one by appending digits to ensure uniqueness)

    :raises OSError: if writing files fails for an unanticipated reason,
        such as a full disk or a lack of permission to write to
        specified location.

    """
    preferred_path = os.path.join(path, "%s.conf" % (filename))
    try:
        return safe_open(preferred_path, chmod=chmod), preferred_path
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise
    return _unique_file(
        path, filename_pat=(lambda count: "%s-%04d.conf" % (filename, count)),
        count=1, chmod=chmod, mode=mode)


def safely_remove(path):
    """Remove a file that may not exist."""
    try:
        os.remove(path)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise


def get_filtered_names(all_names):
    """Removes names that aren't considered valid by Let's Encrypt.

    :param set all_names: all names found in the configuration

    :returns: all found names that are considered valid by LE
    :rtype: set

    """
    filtered_names = set()
    for name in all_names:
        try:
            filtered_names.add(enforce_le_validity(name))
        except errors.ConfigurationError:
            logger.debug('Not suggesting name "%s"', name, exc_info=True)
    return filtered_names

def get_os_info():
    """
    Get OS name and version

    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """

    return get_python_os_info(pretty=False)

def get_os_info_ua():
    """
    Get OS name and version string for User Agent

    :returns: os_ua
    :rtype: `str`
    """
    if _USE_DISTRO:
        os_info = distro.name(pretty=True)

    if not _USE_DISTRO or not os_info:
        return " ".join(get_python_os_info(pretty=True))
    return os_info

def get_systemd_os_like():
    """
    Get a list of strings that indicate the distribution likeness to
    other distributions.

    :returns: List of distribution acronyms
    :rtype: `list` of `str`
    """

    if _USE_DISTRO:
        return distro.like().split(" ")
    return []

def get_var_from_file(varname, filepath="/etc/os-release"):
    """
    Get single value from a file formatted like systemd /etc/os-release

    :param str varname: Name of variable to fetch
    :param str filepath: File path of os-release file
    :returns: requested value
    :rtype: `str`
    """

    var_string = varname+"="
    if not os.path.isfile(filepath):
        return ""
    with open(filepath, 'r') as fh:
        contents = fh.readlines()

    for line in contents:
        if line.strip().startswith(var_string):
            # Return the value of var, normalized
            return _normalize_string(line.strip()[len(var_string):])
    return ""

def _normalize_string(orig):
    """
    Helper function for get_var_from_file() to remove quotes
    and whitespaces
    """
    return orig.replace('"', '').replace("'", "").strip()

def get_python_os_info(pretty=False):
    """
    Get Operating System type/distribution and major version
    using python platform module

    :param bool pretty: If the returned OS name should be in longer (pretty) form

    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """
    info = platform.system_alias(
        platform.system(),
        platform.release(),
        platform.version()
    )
    os_type, os_ver, _ = info
    os_type = os_type.lower()
    if os_type.startswith('linux') and _USE_DISTRO:
        info = distro.linux_distribution(pretty)
        # On arch, distro.linux_distribution() is reportedly ('','',''),
        # so handle it defensively
        if info[0]:
            os_type = info[0]
        if info[1]:
            os_ver = info[1]
    elif os_type.startswith('darwin'):
        try:
            proc = subprocess.Popen(
                ["/usr/bin/sw_vers", "-productVersion"],
                stdout=subprocess.PIPE,
                universal_newlines=True,
                env=env_no_snap_for_external_calls(),
            )
        except OSError:
            proc = subprocess.Popen(
                ["sw_vers", "-productVersion"],
                stdout=subprocess.PIPE,
                universal_newlines=True,
                env=env_no_snap_for_external_calls(),
            )
        os_ver = proc.communicate()[0].rstrip('\n')
    elif os_type.startswith('freebsd'):
        # eg "9.3-RC3-p1"
        os_ver = os_ver.partition("-")[0]
        os_ver = os_ver.partition(".")[0]
    elif platform.win32_ver()[1]:
        os_ver = platform.win32_ver()[1]
    else:
        # Cases known to fall here: Cygwin python
        os_ver = ''
    return os_type, os_ver

# Just make sure we don't get pwned... Make sure that it also doesn't
# start with a period or have two consecutive periods <- this needs to
# be done in addition to the regex
EMAIL_REGEX = re.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$")


def safe_email(email):
    """Scrub email address before using it."""
    if EMAIL_REGEX.match(email) is not None:
        return not email.startswith(".") and ".." not in email
    logger.warning("Invalid email address: %s.", email)
    return False


class _ShowWarning(argparse.Action):
    """Action to log a warning when an argument is used."""
    def __call__(self, unused1, unused2, unused3, option_string=None):
        logger.warning("Use of %s is deprecated.", option_string)


def add_deprecated_argument(add_argument, argument_name, nargs):
    """Adds a deprecated argument with the name argument_name.

    Deprecated arguments are not shown in the help. If they are used on
    the command line, a warning is shown stating that the argument is
    deprecated and no other action is taken.

    :param callable add_argument: Function that adds arguments to an
        argument parser/group.
    :param str argument_name: Name of deprecated argument.
    :param nargs: Value for nargs when adding the argument to argparse.

    """
    if _ShowWarning not in configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE:
        # In version 0.12.0 ACTION_TYPES_THAT_DONT_NEED_A_VALUE was
        # changed from a set to a tuple.
        if isinstance(configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE, set):
            configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE.add(
                _ShowWarning)
        else:
            configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE += (
                _ShowWarning,)
    add_argument(argument_name, action=_ShowWarning,
                 help=argparse.SUPPRESS, nargs=nargs)


def enforce_le_validity(domain):
    """Checks that Let's Encrypt will consider domain to be valid.

    :param str domain: FQDN to check
    :type domain: `str` or `unicode`
    :returns: The domain cast to `str`, with ASCII-only contents
    :rtype: str
    :raises ConfigurationError: for invalid domains and cases where Let's
                                Encrypt currently will not issue certificates

    """
    domain = enforce_domain_sanity(domain)
    if not re.match("^[A-Za-z0-9.-]*$", domain):
        raise errors.ConfigurationError(
            "{0} contains an invalid character. "
            "Valid characters are A-Z, a-z, 0-9, ., and -.".format(domain))

    labels = domain.split(".")
    if len(labels) < 2:
        raise errors.ConfigurationError(
            "{0} needs at least two labels".format(domain))
    for label in labels:
        if label.startswith("-"):
            raise errors.ConfigurationError(
                'label "{0}" in domain "{1}" cannot start with "-"'.format(
                    label, domain))
        if label.endswith("-"):
            raise errors.ConfigurationError(
                'label "{0}" in domain "{1}" cannot end with "-"'.format(
                    label, domain))
    return domain

def enforce_domain_sanity(domain):
    """Method which validates domain value and errors out if
    the requirements are not met.

    :param domain: Domain to check
    :type domain: `str` or `unicode`
    :raises ConfigurationError: for invalid domains and cases where Let's
                                Encrypt currently will not issue certificates

    :returns: The domain cast to `str`, with ASCII-only contents
    :rtype: str
    """
    # Unicode
    try:
        if isinstance(domain, six.binary_type):
            domain = domain.decode('utf-8')
        domain.encode('ascii')
    except UnicodeError:
        raise errors.ConfigurationError("Non-ASCII domain names not supported. "
            "To issue for an Internationalized Domain Name, use Punycode.")

    domain = domain.lower()

    # Remove trailing dot
    domain = domain[:-1] if domain.endswith(u'.') else domain

    # Separately check for odd "domains" like "http://example.com" to fail
    # fast and provide a clear error message
    for scheme in ["http", "https"]:  # Other schemes seem unlikely
        if domain.startswith("{0}://".format(scheme)):
            raise errors.ConfigurationError(
                "Requested name {0} appears to be a URL, not a FQDN. "
                "Try again without the leading \"{1}://\".".format(
                    domain, scheme
                )
            )

    # Explain separately that IP addresses aren't allowed (apart from not
    # being FQDNs) because hope springs eternal concerning this point
    try:
        socket.inet_aton(domain)
        raise errors.ConfigurationError(
            "Requested name {0} is an IP address. The Let's Encrypt "
            "certificate authority will not issue certificates for a "
            "bare IP address.".format(domain))
    except socket.error:
        # It wasn't an IP address, so that's good
        pass

    # FQDN checks according to RFC 2181: domain name should be less than 255
    # octets (inclusive). And each label is 1 - 63 octets (inclusive).
    # https://tools.ietf.org/html/rfc2181#section-11
    msg = "Requested domain {0} is not a FQDN because".format(domain)
    if len(domain) > 255:
        raise errors.ConfigurationError("{0} it is too long.".format(msg))
    labels = domain.split('.')
    for l in labels:
        if not l:
            raise errors.ConfigurationError("{0} it contains an empty label.".format(msg))
        if len(l) > 63:
            raise errors.ConfigurationError("{0} label {1} is too long.".format(msg, l))

    return domain


def is_wildcard_domain(domain):
    """"Is domain a wildcard domain?

    :param domain: domain to check
    :type domain: `bytes` or `str` or `unicode`

    :returns: True if domain is a wildcard, otherwise, False
    :rtype: bool

    """
    if isinstance(domain, six.text_type):
        wildcard_marker = u"*."
    else:
        wildcard_marker = b"*."

    return domain.startswith(wildcard_marker)


def get_strict_version(normalized):
    """Converts a normalized version to a strict version.

    :param str normalized: normalized version string

    :returns: An equivalent strict version
    :rtype: distutils.version.StrictVersion

    """
    # strict version ending with "a" and a number designates a pre-release
    return distutils.version.StrictVersion(normalized.replace(".dev", "a"))


def is_staging(srv):
    """
    Determine whether a given ACME server is a known test / staging server.

    :param str srv: the URI for the ACME server
    :returns: True iff srv is a known test / staging server
    :rtype bool:
    """
    return srv == constants.STAGING_URI or "staging" in srv


def atexit_register(func, *args, **kwargs):
    """Sets func to be called before the program exits.

    Special care is taken to ensure func is only called when the process
    that first imports this module exits rather than any child processes.

    :param function func: function to be called in case of an error

    """
    atexit.register(_atexit_call, func, *args, **kwargs)


def _atexit_call(func, *args, **kwargs):
    if _INITIAL_PID == os.getpid():
        func(*args, **kwargs)
