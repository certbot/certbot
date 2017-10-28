"""Utility functions for use in the Postfix installer."""

import logging
import subprocess

from certbot import errors
from certbot import util as certbot_util
from certbot.plugins import util as plugins_util


logger = logging.getLogger(__name__)


def check_all_output(*args, **kwargs):
    """A version of subprocess.check_output that also captures stderr.

    This is the same as :func:`subprocess.check_output` except output
    written to stderr is also captured and returned to the caller. The
    return value is a tuple of two strings (rather than byte strings).
    To accomplish this, the caller cannot set the stdout, stderr, or
    universal_newlines parameters to :class:`subprocess.Popen`.

    Additionally, if the command exits with a nonzero status, output is
    not included in the raised :class:`subprocess.CalledProcessError`
    because Python 2.6 does not support this. Instead, the failure
    including the output is logged.

    :param tuple args: positional arguments for Popen
    :param dict kwargs: keyword arguments for Popen

    :returns: data written to stdout and stderr
    :rtype: `tuple` of `str`

    :raises ValueError: if arguments are invalid
    :raises subprocess.CalledProcessError: if the command fails

    """
    for keyword in ('stdout', 'stderr', 'universal_newlines',):
        if keyword in kwargs:
            raise ValueError(
                keyword + ' argument not allowed, it will be overridden.')

    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.PIPE
    kwargs['universal_newlines'] = True

    process = subprocess.Popen(*args, **kwargs)
    output, err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get('args')
        if cmd is None:
            cmd = args[0]
        logger.debug(
            "'%s' exited with %d. stdout output was:\n%s\nstderr output was:\n%s",
            cmd, retcode, output, err)
        raise subprocess.CalledProcessError(retcode, cmd)
    return (output, err)


def verify_exe_exists(exe):
    """Ensures an executable with the given name is available.

    If an executable isn't found for the given path or name, extra
    directories are added to the user's PATH to help find system
    utilities that may not be available in the default cron PATH.

    :param str exe: executable path or name

    :raises .NoInstallationError: when the executable isn't found

    """
    if not (certbot_util.exe_exists(exe) or plugins_util.path_surgery(exe)):
        raise errors.NoInstallationError(
            "Cannot find executable '{0}'.".format(exe))


def check_call(*args, **kwargs):
    """A simple wrapper of subprocess.check_call that logs errors.

    :param tuple args: positional arguments to subprocess.check_call
    :param dict kargs: keyword arguments to subprocess.check_call

    :raises subprocess.CalledProcessError: if the call fails

    """
    try:
        subprocess.check_call(*args, **kwargs)
    except subprocess.CalledProcessError:
        cmd = _get_cmd(*args, **kwargs)
        logger.debug("%s exited with a non-zero status.",
                     "".join(cmd), exc_info=True)
        raise


def check_output(*args, **kwargs):
    """Backported version of subprocess.check_output for Python 2.6+.

    This is the same as subprocess.check_output from newer versions of
    Python, except:

    1. The return value is a string rather than a byte string. To
    accomplish this, the caller cannot set the parameter
    universal_newlines.
    2. If the command exits with a nonzero status, output is not
    included in the raised subprocess.CalledProcessError because
    subprocess.CalledProcessError on Python 2.6 does not support this.
    Instead, the failure including the output is logged.

    :param tuple args: positional arguments for Popen
    :param dict kwargs: keyword arguments for Popen

    :returns: data printed to stdout
    :rtype: str

    :raises ValueError: if arguments are invalid
    :raises subprocess.CalledProcessError: if the command fails

    """
    for keyword in ('stdout', 'universal_newlines',):
        if keyword in kwargs:
            raise ValueError(
                keyword + ' argument not allowed, it will be overridden.')

    kwargs['stdout'] = subprocess.PIPE
    kwargs['universal_newlines'] = True

    process = subprocess.Popen(*args, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = _get_cmd(*args, **kwargs)
        logger.debug(
            "'%s' exited with %d. Output was:\n%s",
            cmd, retcode, output, exc_info=True)
        raise subprocess.CalledProcessError(retcode, cmd)
    return output


def _get_cmd(*args, **kwargs):
    """Return the command from Popen args.

    :param tuple args: Popen args
    :param dict kwargs: Popen kwargs

    """
    cmd = kwargs.get('args')
    return args[0] if cmd is None else cmd
