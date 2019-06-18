"""Verifies certbot-auto cannot be modified by unprivileged users.

This script takes the path to certbot-auto as its only command line
argument.  It then checks that the file can only be modified by uid/gid
< 1000 and if other users can modify the file, it prints a warning with
a suggestion on how to solve the problem.

Permissions on symlinks in the absolute path of certbot-auto are ignored
and only the canonical path to certbot-auto is checked. There could be
permissions problems due to the symlinks that are unreported by this
script, however, issues like this were not caused by our documentation
and are ignored for the sake of simplicity.

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
    uid/gid < 1000.

    The reason we allow more IDs than 0 is because on some systems such
    as Debian, system users/groups other than uid/gid 0 are used for the
    path we recommend in our instructions which is /usr/local/bin.  1000
    was chosen because on Debian 0-999 is reserved for system IDs[1] and
    on RHEL either 0-499 or 0-999 is reserved depending on the
    version[2][3]. Due to these differences across different OSes, this
    detection isn't perfect so we only determine permissions are
    insecure when we can be reasonably confident there is a problem
    regardless of the underlying OS.

    [1] https://www.debian.org/doc/debian-policy/ch-opersys.html#uid-and-gid-classes
    [2] https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/ch-managing_users_and_groups
    [3] https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-managing_users_and_groups

    :param str path: filesystem path to check
    :returns: True if the path has secure permissions, otherwise, False
    :rtype: bool

    """
    # os.stat follows symlinks before obtaining information about a file.
    stat_result = os.stat(path)
    if stat_result.st_mode & stat.S_IWOTH:
        return False
    if stat_result.st_mode & stat.S_IWGRP and stat_result.st_gid >= 1000:
        return False
    if stat_result.st_mode & stat.S_IWUSR and stat_result.st_uid >= 1000:
        return False
    return True


def main(certbot_auto_path):
    current_path = os.path.realpath(certbot_auto_path)
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
