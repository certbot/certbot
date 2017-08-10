"""Utility functions for use in the Postfix installer."""

import logging
import subprocess


logger = logging.getLogger(__name__)


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
        cmd = kwargs.get('args')
        if cmd is None:
            cmd = args[0]
        logger.debug(
            "'%s' exited with %d. Output was:\n%s", cmd, retcode, output)
        raise subprocess.CalledProcessError(retcode, cmd)
    return output
