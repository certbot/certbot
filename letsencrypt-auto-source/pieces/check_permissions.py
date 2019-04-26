"""Verifies certbot-auto cannot be modified by unprivileged users.

This script takes the path to certbot-auto as its only command line
argument. It then checks that the file can only be modified by uid/gid 0
and if other users can modify the file, it prints a warning with a
suggestion on how to solve the problem.

If the absolute path of certbot-auto contains a symlink, it is not
handled specially and the symlink is followed. Due to this, there could
be permissions problems unreported by this script, however, issues like
this were not caused by our documentation and are ignored for the sake
of simplicity.

All warnings are printed to stdout rather than stderr so all stderr
output from this script can be suppressed to avoid printing messages if
this script fails for some reason.

"""
from __future__ import print_function

import os
import stat
import sys


FORUM_POST_URL = 'https://community.letsencrypt.org/t/certbot-auto-deployment-best-practices/91979/'


def has_safe_permissions(path):
    """Returns True if the given path has secure permissions.

    The permissions are considered safe if the file is only writable by
    uid/gid 0.

    :param str path: filesystem path to check
    :returns: True if the path has secure permissions, otherwise, False
    :rtype: bool

    """
    stat_result = os.stat(path)
    if stat_result.st_mode & stat.S_IWOTH:
        return False
    if stat_result.st_mode & stat.S_IWGRP and stat_result.st_gid != 0:
        return False
    if stat_result.st_mode & stat.S_IWUSR and stat_result.st_uid != 0:
        return False
    return True


def main(certbot_auto_path):
    current_path = os.path.abspath(certbot_auto_path)
    last_path = None
    permissions_ok = True
    # This loop makes use of the fact that os.path.dirname('/') == '/'.
    while current_path != last_path and permissions_ok:
        permissions_ok = has_safe_permissions(current_path)
        last_path = current_path
        current_path = os.path.dirname(current_path)

    if not permissions_ok:
        print('{0} has insecure permissions!'.format(certbot_auto_path))
        print('To learn how to fix them, visit {0}'.format(FORUM_POST_URL))


if __name__ == '__main__':
    main(sys.argv[1])
