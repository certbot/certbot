"""Utilities for all Let's Encrypt."""
import argparse
import collections
import errno
import logging
import os
import platform
import re
import stat
import subprocess
import sys

import configargparse

from letsencrypt import errors


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


def run_script(params):
    """Run the script with the given params.

    :param list params: List of parameters to pass to Popen

    """
    try:
        proc = subprocess.Popen(params,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

    except (OSError, ValueError):
        msg = "Unable to run the command: %s" % " ".join(params)
        logger.error(msg)
        raise errors.SubprocessError(msg)

    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        msg = "Error while running %s.\n%s\n%s" % (
            " ".join(params), stdout, stderr)
        # Enter recovery routine...
        logger.error(msg)
        raise errors.SubprocessError(msg)

    return stdout, stderr


def exe_exists(exe):
    """Determine whether path/name refers to an executable.

    :param str exe: Executable path or name

    :returns: If exe is a valid executable
    :rtype: bool

    """
    def is_exe(path):
        """Determine if path is an exe."""
        return os.path.isfile(path) and os.access(path, os.X_OK)

    path, _ = os.path.split(exe)
    if path:
        return is_exe(exe)
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            if is_exe(os.path.join(path, exe)):
                return True

    return False


def make_or_verify_dir(directory, mode=0o755, uid=0, strict=False):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.

    :raises .errors.Error: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if strict and not check_permissions(directory, mode, uid):
                raise errors.Error(
                    "%s exists, but it should be owned by user %d with"
                    "permissions %s" % (directory, uid, oct(mode)))
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param str filepath: Path to the tested file (or directory).
    :param int mode: Expected file mode.
    :param int uid: Expected file owner.

    :returns: True if `mode` and `uid` match, False otherwise.
    :rtype: bool

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def safe_open(path, mode="w", chmod=None, buffering=None):
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.

    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    return os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, *open_args),
        mode, *fdopen_args)


def _unique_file(path, filename_pat, count, mode):
    while True:
        current_path = os.path.join(path, filename_pat(count))
        try:
            return safe_open(current_path, chmod=mode), current_path
        except OSError as err:
            # "File exists," is okay, try a different name.
            if err.errno != errno.EEXIST:
                raise
        count += 1


def unique_file(path, mode=0o777):
    """Safely finds a unique file.

    :param str path: path/filename.ext
    :param int mode: File mode

    :returns: tuple of file object and file name

    """
    path, tail = os.path.split(path)
    return _unique_file(
        path, filename_pat=(lambda count: "%04d_%s" % (count, tail)),
        count=0, mode=mode)


def unique_lineage_name(path, filename, mode=0o777):
    """Safely finds a unique file using lineage convention.

    :param str path: directory path
    :param str filename: proposed filename
    :param int mode: file mode

    :returns: tuple of file object and file name (which may be modified
        from the requested one by appending digits to ensure uniqueness)

    :raises OSError: if writing files fails for an unanticipated reason,
        such as a full disk or a lack of permission to write to
        specified location.

    """
    preferred_path = os.path.join(path, "%s.conf" % (filename))
    try:
        return safe_open(preferred_path, chmod=mode), preferred_path
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise
    return _unique_file(
        path, filename_pat=(lambda count: "%s-%04d.conf" % (filename, count)),
        count=1, mode=mode)


def safely_remove(path):
    """Remove a file that may not exist."""
    try:
        os.remove(path)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise


def get_os_info():
    """
    Get Operating System type/distribution and major version

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
    if os_type.startswith('linux'):
        info = platform.linux_distribution()
        # On arch, platform.linux_distribution() is reportedly ('','',''),
        # so handle it defensively
        if info[0]:
            os_type = info[0]
        if info[1]:
            os_ver = info[1]
    elif os_type.startswith('darwin'):
        os_ver = subprocess.Popen(
            ["sw_vers", "-productVersion"],
            stdout=subprocess.PIPE
        ).communicate()[0]
        os_ver = os_ver.partition(".")[0]
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
    else:
        logger.warn("Invalid email address: %s.", email)
        return False


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
    class ShowWarning(argparse.Action):
        """Action to log a warning when an argument is used."""
        def __call__(self, unused1, unused2, unused3, option_string=None):
            sys.stderr.write(
                "Use of {0} is deprecated.\n".format(option_string))

    configargparse.ACTION_TYPES_THAT_DONT_NEED_A_VALUE.add(ShowWarning)
    add_argument(argument_name, action=ShowWarning,
                 help=argparse.SUPPRESS, nargs=nargs)


def enforce_domain_sanity(domain):
    """Method which validates domain value and errors out if
    the requirements are not met.

    :param domain: Domain to check
    :type domains: `str` or `unicode`
    :raises ConfigurationError: for invalid domains and cases where Let's
                                Encrypt currently will not issue certificates

    :returns: The domain cast to `str`, with ASCII-only contents
    :rtype: str
    """
    # Check if there's a wildcard domain
    if domain.startswith("*."):
        raise errors.ConfigurationError(
            "Wildcard domains are not supported: {0}".format(domain))
    # Punycode
    if "xn--" in domain:
        raise errors.ConfigurationError(
            "Punycode domains are not presently supported: {0}".format(domain))

    # Unicode
    try:
        domain = domain.encode('ascii').lower()
    except UnicodeDecodeError:
        raise errors.ConfigurationError(
            "Internationalized domain names are not presently supported: {0}"
            .format(domain))

    # Remove trailing dot
    domain = domain[:-1] if domain.endswith('.') else domain

    # FQDN checks from
    # http://www.mkyong.com/regular-expressions/domain-name-regular-expression-example/
    #  Characters used, domain parts < 63 chars, tld > 1 < 64 chars
    #  first and last char is not "-"
    fqdn = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,63}$")
    if not fqdn.match(domain):
        raise errors.ConfigurationError("Requested domain {0} is not a FQDN".format(domain))
    return domain
