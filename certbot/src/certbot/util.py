"""Utilities for all Certbot."""
import argparse
import atexit
import errno
import itertools
import logging
import platform
import re
import socket
import subprocess
import sys
from typing import Any
from typing import Callable
from typing import IO
from typing import NamedTuple
from typing import Optional
from typing import Union

import configargparse

from certbot import errors
from certbot._internal import constants
from certbot._internal import lock
from certbot.compat import filesystem
from certbot.compat import os

_USE_DISTRO = sys.platform.startswith('linux')
if _USE_DISTRO:
    import distro

logger = logging.getLogger(__name__)


class Key(NamedTuple):
    """Container for an optional file path and contents for a PEM-formated private key."""
    file: Optional[str]
    pem: bytes


class CSR(NamedTuple):
    """Container for an optional file path and contents for a PEM or DER-formatted CSR."""
    file: Optional[str]
    data: bytes
    # Note: form is the type of data, "pem" or "der"
    form: str


class LooseVersion:
    """A version with loose rules, i.e. any given string is a valid version number.

    but regular comparison is not supported. Instead, the `try_risky_comparison` method is
    provided, which may return an error if two LooseVersions are 'incomparible'.
    For example when integer and string version components are present in the same position.

    Differences with old distutils.version.LooseVersion:
    (https://github.com/python/cpython/blob/v3.10.0/Lib/distutils/version.py#L269)
    Most version comparisons should give the same result. However, if a version has multiple
    trailing zeroes, not all of them are used in the comparison. This ensure that, for example,
    "2.0" and "2.0.0" are equal.
    """

    def __init__(self, version_string: str) -> None:
        """Parses a version string into its components.

        :param str version_string: version string
        """
        components: list[Union[int, str]]
        components = [x for x in _VERSION_COMPONENT_RE.split(version_string)
                              if x and x != '.']
        for i, obj in enumerate(components):
            try:
                components[i] = int(obj)
            except ValueError:
                pass

        self.version_components = components

    def try_risky_comparison(self, other: 'LooseVersion') -> int:
        """Compares the LooseVersion to another value.

        If the other value is another LooseVersion, the version components are compared. Otherwise,
        an exception is raised.

        Comparison is performed element-wise. If the version components being compared are of
        different types, the two versions are considered incompatible. Otherwise, if either of the
        components is not equal to the other, less or greater is returned based on the comparison's
        result. In case the two versions are of different lengths, some elements in the longer
        version have not yet been compared. If these are all equal to zero, the two versions are
        equal. Otherwise, the longer version is greater.

        If the two versions are incompatible, an exception is raised. Otherwise, the returned
        integer indicates the result of the comparison. If self == other, 0 is returned.
        If self > other, 1 is returned. If self < other -1 is returned.

        Examples:
        Equality:
        - LooseVersion('1.0').try_risky_comparison(LooseVersion('1.0')) -> 0
        - LooseVersion('2.0.0a').try_risky_comparison(LooseVersion('2.0.0a')) -> 0
        Inequality:
        - LooseVersion('2.0.0').try_risky_comparison(LooseVersion('1.0')) -> 1
        - LooseVersion('1.0.1').try_risky_comparison(LooseVersion('2.0a')) -> -1
        Incomparability:
        - LooseVersion('1a').try_risky_comparison(LooseVersion('1.0')) -> ValueError
        """
        try:
            for self_vc, other_vc in itertools.zip_longest(self.version_components,
                                                           other.version_components,
                                                           fillvalue=0):
                # ensure mypy ignores types here and catch any TypeErrors
                if self_vc < other_vc:  # type: ignore
                    return -1
                elif self_vc > other_vc:  # type: ignore
                    return 1
            return 0
        except TypeError:
            raise ValueError("Cannot meaningfully compare LooseVersion {} with LooseVersion {} "
                             "due to comparison of version components with different types."
                             .format(self.version_components, other.version_components))


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
_LOCKS: dict[str, lock.LockFile] = {}
_VERSION_COMPONENT_RE = re.compile(r'(\d+ | [a-z]+ | \.)', re.VERBOSE)

def env_no_snap_for_external_calls() -> dict[str, str]:
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

    # These environment variables being set when running external programs can cause issues if these
    # programs also use OpenSSL. See https://github.com/certbot/certbot/issues/10190.
    env.pop('OPENSSL_FORCE_FIPS_MODE', None)
    env.pop('OPENSSL_MODULES', None)

    for path_name in ('PATH', 'LD_LIBRARY_PATH'):
        if path_name in env:
            env[path_name] = ':'.join(x for x in env[path_name].split(':') if env['SNAP'] not in x)
    return env


def run_script(params: list[str], log: Callable[[str], None]=logger.error) -> tuple[str, str]:
    """Run the script with the given params.

    :param list params: List of parameters to pass to subprocess.run
    :param callable log: Logger method to use for errors

    """
    try:
        proc = subprocess.run(params,
                              check=False,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              universal_newlines=True,
                              env=env_no_snap_for_external_calls())

    except (OSError, ValueError):
        msg = "Unable to run the command: %s" % " ".join(params)
        log(msg)
        raise errors.SubprocessError(msg)

    if proc.returncode != 0:
        msg = "Error while running %s.\n%s\n%s" % (
            " ".join(params), proc.stdout, proc.stderr)
        # Enter recovery routine...
        log(msg)
        raise errors.SubprocessError(msg)

    return proc.stdout, proc.stderr


def exe_exists(exe: str) -> bool:
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


def lock_dir_until_exit(dir_path: str) -> None:
    """Lock the directory at dir_path until program exit.

    :param str dir_path: path to directory

    :raises errors.LockError: if the lock is held by another process

    """
    if not _LOCKS:  # this is the first lock to be released at exit
        atexit_register(_release_locks)

    if dir_path not in _LOCKS:
        _LOCKS[dir_path] = lock.lock_dir(dir_path)


def _release_locks() -> None:
    for dir_lock in _LOCKS.values():
        try:
            dir_lock.release()
        except:  # pylint: disable=bare-except
            msg = 'Exception occurred releasing lock: {0!r}'.format(dir_lock)
            logger.debug(msg, exc_info=True)
    _LOCKS.clear()


def set_up_core_dir(directory: str, mode: int, strict: bool) -> None:
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


def make_or_verify_dir(directory: str, mode: int = 0o755, strict: bool = False) -> None:
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


def safe_open(path: str, mode: str = "w", chmod: Optional[int] = None) -> IO:
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `filesystem.open`, uses Python defaults
        if ``None``.

    """
    open_args: Union[tuple[()], tuple[int]] = ()
    if chmod is not None:
        open_args = (chmod,)
    fdopen_args: Union[tuple[()], tuple[int]] = ()
    fd = filesystem.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, *open_args)
    return os.fdopen(fd, mode, *fdopen_args)


def _unique_file(path: str, filename_pat: Callable[[int], str], count: int,
                 chmod: int, mode: str) -> tuple[IO, str]:
    while True:
        current_path = os.path.join(path, filename_pat(count))
        try:
            return safe_open(current_path, chmod=chmod, mode=mode), os.path.abspath(current_path)
        except OSError as err:
            # "File exists," is okay, try a different name.
            if err.errno != errno.EEXIST:
                raise
        count += 1


def unique_file(path: str, chmod: int = 0o600, mode: str = "w") -> tuple[IO, str]:
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


def unique_lineage_name(path: str, filename: str, chmod: int = 0o644,
                        mode: str = "w") -> tuple[IO, str]:
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


def safely_remove(path: str) -> None:
    """Remove a file that may not exist."""
    try:
        os.remove(path)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise


def get_filtered_names(all_names: set[str]) -> set[str]:
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

def get_os_info() -> tuple[str, str]:
    """
    Get OS name and version

    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """

    return get_python_os_info(pretty=False)

def get_os_info_ua() -> str:
    """
    Get OS name and version string for User Agent

    :returns: os_ua
    :rtype: `str`

    """
    # distro.name returns an empty string if one cannot be determined. see
    # https://github.com/python-distro/distro/blob/3bd19e61fcb7f8d2bf3d45d9e40d69c92e05d241/src/distro/distro.py#L883
    os_info = ""
    if _USE_DISTRO:
        os_info = distro.name(pretty=True)

    if not _USE_DISTRO or not os_info:
        return " ".join(get_python_os_info(pretty=True))
    return os_info

def get_systemd_os_like() -> list[str]:
    """
    Get a list of strings that indicate the distribution likeness to
    other distributions.

    :returns: List of distribution acronyms
    :rtype: `list` of `str`
    """

    if _USE_DISTRO:
        return distro.like().split(" ")
    return []

def get_var_from_file(varname: str, filepath: str = "/etc/os-release") -> str:
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

def _normalize_string(orig: str) -> str:
    """
    Helper function for get_var_from_file() to remove quotes
    and whitespaces
    """
    return orig.replace('"', '').replace("'", "").strip()

def get_python_os_info(pretty: bool = False) -> tuple[str, str]:
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
        distro_name, distro_version = distro.name() if pretty else distro.id(), distro.version()
        # On arch, these values are reportedly empty strings so handle it
        # defensively
        # so handle it defensively
        if distro_name:
            os_type = distro_name
        if distro_version:
            os_ver = distro_version
    elif os_type.startswith('darwin'):
        try:
            proc = subprocess.run(
                ["/usr/bin/sw_vers", "-productVersion"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, universal_newlines=True,
                env=env_no_snap_for_external_calls(),
            )
        except OSError:
            proc = subprocess.run(
                ["sw_vers", "-productVersion"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, universal_newlines=True,
                env=env_no_snap_for_external_calls(),
            )
        os_ver = proc.stdout.rstrip('\n')
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


def safe_email(email: str) -> bool:
    """Scrub email address before using it."""
    if EMAIL_REGEX.match(email) is not None:
        return not email.startswith(".") and ".." not in email
    logger.error("Invalid email address: %s.", email)
    return False


class DeprecatedArgumentAction(argparse.Action):
    """Action to log a warning when an argument is used."""
    def __call__(self, unused1: Any, unused2: Any, unused3: Any,
                 option_string: Optional[str] = None) -> None:
        logger.warning("Use of %s is deprecated.", option_string)


def add_deprecated_argument(add_argument: Callable[..., None], argument_name: str,
                            nargs: Union[str, int]) -> None:
    """Adds a deprecated argument with the name argument_name.

    Deprecated arguments are not shown in the help. If they are used on
    the command line, a warning is shown stating that the argument is
    deprecated and no other action is taken.

    :param callable add_argument: Function that adds arguments to an
        argument parser/group.
    :param str argument_name: Name of deprecated argument.
    :param nargs: Value for nargs when adding the argument to argparse.

    """
    if DeprecatedArgumentAction not in configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE:
        # In version 0.12.0 ACTION_TYPES_THAT_DONT_NEED_A_VALUE was
        # changed from a set to a tuple.
        if isinstance(configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE, set):
            configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE.add(
                DeprecatedArgumentAction)
        else:
            configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE += (
                DeprecatedArgumentAction,)
    add_argument(argument_name, action=DeprecatedArgumentAction,
                 help=argparse.SUPPRESS, nargs=nargs)


def enforce_le_validity(domain: str) -> str:
    """Checks that Let's Encrypt will consider domain to be valid.

    :param str domain: FQDN to check
    :type domain: `str`
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


def enforce_domain_sanity(domain: Union[str, bytes]) -> str:
    """Method which validates domain value and errors out if
    the requirements are not met.

    :param domain: Domain to check
    :type domain: `str` or `bytes`
    :raises ConfigurationError: for invalid domains and cases where Let's
                                Encrypt currently will not issue certificates

    :returns: The domain cast to `str`, with ASCII-only contents
    :rtype: str
    """
    # Unicode
    try:
        if isinstance(domain, bytes):
            domain = domain.decode('utf-8')
        domain.encode('ascii')
    except UnicodeError:
        raise errors.ConfigurationError("Non-ASCII domain names not supported. "
            "To issue for an Internationalized Domain Name, use Punycode.")

    domain = domain.lower()

    # Remove trailing dot
    domain = domain[:-1] if domain.endswith('.') else domain

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

    if is_ipaddress(domain):
        raise errors.ConfigurationError(
            "Requested name {0} is an IP address. The Let's Encrypt "
            "certificate authority will not issue certificates for a "
            "bare IP address.".format(domain))

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


def is_ipaddress(address: str) -> bool:
    """Is given address string form of IP(v4 or v6) address?

    :param address: address to check
    :type address: `str`

    :returns: True if address is valid IP address, otherwise return False.
    :rtype: bool

    """
    try:
        socket.inet_pton(socket.AF_INET, address)
        # If this line runs it was ip address (ipv4)
        return True
    except OSError:
        # It wasn't an IPv4 address, so try ipv6
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except OSError:
            return False


def is_wildcard_domain(domain: Union[str, bytes]) -> bool:
    """"Is domain a wildcard domain?

    :param domain: domain to check
    :type domain: `bytes` or `str`

    :returns: True if domain is a wildcard, otherwise, False
    :rtype: bool

    """
    if isinstance(domain, str):
        return domain.startswith("*.")
    return domain.startswith(b"*.")


def is_staging(srv: str) -> bool:
    """
    Determine whether a given ACME server is a known test / staging server.

    :param str srv: the URI for the ACME server
    :returns: True iff srv is a known test / staging server
    :rtype bool:
    """
    return srv == constants.STAGING_URI or "staging" in srv


def atexit_register(func: Callable, *args: Any, **kwargs: Any) -> None:
    """Sets func to be called before the program exits.

    Special care is taken to ensure func is only called when the process
    that first imports this module exits rather than any child processes.

    :param function func: function to be called in case of an error

    """
    atexit.register(_atexit_call, func, *args, **kwargs)


def parse_loose_version(version_string: str) -> list[Union[int, str]]:
    """Parses a version string into its components.
    This code and the returned tuple is based on the now deprecated
    distutils.version.LooseVersion class from the Python standard library.
    Two LooseVersion classes and two lists as returned by this function should
    compare in the same way. See
    https://github.com/python/cpython/blob/v3.10.0/Lib/distutils/version.py#L205-L347.
    :param str version_string: version string
    :returns: list of parsed version string components
    :rtype: list
    """
    loose_version = LooseVersion(version_string)
    return loose_version.version_components


def _atexit_call(func: Callable, *args: Any, **kwargs: Any) -> None:
    if _INITIAL_PID == os.getpid():
        func(*args, **kwargs)
