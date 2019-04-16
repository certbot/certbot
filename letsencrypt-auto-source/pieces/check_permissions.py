"""Verifies a file cannot be modified by unprivileged users.

This script takes a path to a file as its only command line argument. It
then checks that the file can only be modified by uid/gid 0 and if other
users can modify the file, it prints a warning with a suggestion on how
to solve the problem.

This script was written for use with the executable script certbot-auto
so if there is a problem with the file permissions, the recommended fix
makes the file executable.

"""
from __future__ import print_function

import os
import stat
import sys


# Directory where we recommend placing certbot-auto.
RECOMMENDED_DIR = '/usr/local/bin'


def get_permissions_problems(path):
    """Returns warnings to be printed about the file at the given path."""
    problems = []
    stat_result = os.stat(path)
    if stat_result.st_mode & stat.S_IWOTH:
        problems.append('{0} is world writable!'.format(path))
    if stat_result.st_mode & stat.S_IWGRP and stat_result.st_gid != 0:
        problems.append('{0} is writable by a '
                        'group other than group id 0!'.format(path))
    if stat_result.st_mode & stat.S_IWUSR and stat_result.st_uid != 0:
        problems.append('{0} is writable by users other than root!'.format(path))

    return problems


def stderr_print(*args):
    """Prints messages to stderr instead of stdout."""
    print(*args, file=sys.stderr)


def main(important_file):
    important_file = os.path.abspath(important_file)
    file_problems = get_permissions_problems(important_file)
    if file_problems:
        stderr_print('\n'.join(file_problems))
        stderr_print('To fix this, run the commands:')
        stderr_print('\tsudo chown root {0}'.format(important_file))
        stderr_print('\tsudo chmod 0755 {0}'.format(important_file))

    directory = os.path.dirname(important_file)
    dir_problems = get_permissions_problems(directory)
    if dir_problems:
        if file_problems:
            # Print a blank line to separate file and directory output.
            stderr_print()
        stderr_print('\n'.join(dir_problems))
        stderr_print('This is a problem because '
                     'this directory contains {0}.'.format(os.path.basename(important_file)))
        if os.path.exists(RECOMMENDED_DIR) and not get_permissions_problems(RECOMMENDED_DIR):
            stderr_print('To fix this, we recommend moving {0} to {1}.'.format(important_file,
                                                                               RECOMMENDED_DIR))
        else:
            stderr_print('To fix this, we recommend moving {0} to '
                         'a directory with more restrictive permissions.'.format(important_file))



if __name__ == '__main__':
    main(sys.argv[1])
