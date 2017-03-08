"""Plugin utilities."""
import logging
import os

from certbot import util

logger = logging.getLogger(__name__)


def path_surgery(cmd):
    """Attempt to perform PATH surgery to find cmd

    Mitigates https://github.com/certbot/certbot/issues/1833

    :param str cmd: the command that is being searched for in the PATH

    :returns: True if the operation succeeded, False otherwise
    """
    dirs = ("/usr/sbin", "/usr/local/bin", "/usr/local/sbin")
    path = os.environ["PATH"]
    added = []
    for d in dirs:
        if d not in path:
            path += os.pathsep + d
            added.append(d)

    if any(added):
        logger.debug("Can't find %s, attempting PATH mitigation by adding %s",
                     cmd, os.pathsep.join(added))
        os.environ["PATH"] = path

    if util.exe_exists(cmd):
        return True
    else:
        expanded = " expanded" if any(added) else ""
        logger.warning("Failed to find executable %s in%s PATH: %s", cmd,
                       expanded, path)
        return False
