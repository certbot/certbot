"""Plugin utilities."""
import logging

from certbot import util
from certbot.compat import os
from certbot.compat.misc import STANDARD_BINARY_DIRS

logger = logging.getLogger(__name__)


def get_prefixes(path):
    """Retrieves all possible path prefixes of a path, in descending order
    of length. For instance,
        (linux) /a/b/c returns ['/a/b/c', '/a/b', '/a', '/']
        (windows) C:\\a\\b\\c returns ['C:\\a\\b\\c', 'C:\\a\\b', 'C:\\a', 'C:']
    :param str path: the path to break into prefixes

    :returns: all possible path prefixes of given path in descending order
    :rtype: `list` of `str`
    """
    prefix = os.path.normpath(path)
    prefixes = []
    while prefix:
        prefixes.append(prefix)
        prefix, _ = os.path.split(prefix)
        # break once we hit the root path
        if prefix == prefixes[-1]:
            break
    return prefixes


def path_surgery(cmd):
    """Attempt to perform PATH surgery to find cmd

    Mitigates https://github.com/certbot/certbot/issues/1833

    :param str cmd: the command that is being searched for in the PATH

    :returns: True if the operation succeeded, False otherwise
    """
    path = os.environ["PATH"]
    added = []
    for d in STANDARD_BINARY_DIRS:
        if d not in path:
            path += os.pathsep + d
            added.append(d)

    if any(added):
        logger.debug("Can't find %s, attempting PATH mitigation by adding %s",
                     cmd, os.pathsep.join(added))
        os.environ["PATH"] = path

    if util.exe_exists(cmd):
        return True
    expanded = " expanded" if any(added) else ""
    logger.debug("Failed to find executable %s in%s PATH: %s", cmd,
                 expanded, path)
    return False

def env_no_snap_for_external_calls():
    """
    Returns a modified env to pass to Popen
    """
    env = os.environ.copy()
    if 'SNAP' not in env:
        return env
    for path_name in ('PATH', 'LD_LIBRARY_PATH'):
        if path_name in env:
            env[path_name] = ':'.join(x for x in env[path_name].split(':') if env['SNAP'] not in x)
    return env