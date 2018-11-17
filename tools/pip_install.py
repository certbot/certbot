#!/usr/bin/env python
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, a combination of tools/oldest_constraints.txt,
# tools/dev_constraints.txt, and local-oldest-requirements.txt contained in the
# top level of the package's directory is used, otherwise, a combination of
# certbot-auto's requirements file and tools/dev_constraints.txt is used. The
# other file always takes precedence over tools/dev_constraints.txt. If
# CERTBOT_OLDEST is set, this script must be run with `-e <package-name>` and
# no other arguments.

from __future__ import print_function, absolute_import

import subprocess
import os
import sys
import re
import shutil
import tempfile

import merge_requirements as merge_module
import readlink


def find_tools_path():
    return os.path.dirname(readlink.main(__file__))


def certbot_oldest_processing(tools_path, args, test_constraints):
    if args[0] != '-e' or len(args) != 2:
        raise ValueError('When CERTBOT_OLDEST is set, this script must be run '
                         'with a single -e <path> argument.')
    # remove any extras such as [dev]
    pkg_dir = re.sub(r'\[\w+\]', '', args[1])
    requirements = os.path.join(pkg_dir, 'local-oldest-requirements.txt')
    # packages like acme don't have any local oldest requirements
    if not os.path.isfile(requirements):
        requirements = None
    shutil.copy(os.path.join(tools_path, 'oldest_constraints.txt'), test_constraints)

    return requirements


def certbot_normal_processing(tools_path, test_constraints):
    repo_path = os.path.dirname(tools_path)
    certbot_requirements = os.path.normpath(os.path.join(
        repo_path, 'letsencrypt-auto-source/pieces/dependency-requirements.txt'))
    with open(certbot_requirements, 'r') as fd:
        data = fd.readlines()
    with open(test_constraints, 'w') as fd:
        for line in data:
            search = re.search(r'^(\S*==\S*).*$', line)
            if search:
                fd.write('{0}{1}'.format(search.group(1), os.linesep))


def merge_requirements(tools_path, test_constraints, all_constraints):
    merged_requirements = merge_module.main(
        os.path.join(tools_path, 'dev_constraints.txt'),
        test_constraints
    )
    with open(all_constraints, 'w') as fd:
        fd.write(merged_requirements)


def call_with_print(command, cwd=None):
    print(command)
    subprocess.check_call(command, shell=True, cwd=cwd or os.getcwd())


def main(args):
    tools_path = find_tools_path()
    working_dir = tempfile.mkdtemp()

    try:
        test_constraints = os.path.join(working_dir, 'test_constraints.txt')
        all_constraints = os.path.join(working_dir, 'all_constraints.txt')

        requirements = None
        if os.environ.get('CERTBOT_OLDEST') == '1':
            requirements = certbot_oldest_processing(tools_path, args, test_constraints)
        else:
            certbot_normal_processing(tools_path, test_constraints)

        merge_requirements(tools_path, test_constraints, all_constraints)
        if requirements:
            call_with_print('"{0}" -m pip install -q --constraint "{1}" --requirement "{2}"'
                            .format(sys.executable, all_constraints, requirements))

        call_with_print('"{0}" -m pip install -q --constraint "{1}" {2}'
                        .format(sys.executable, all_constraints, ' '.join(args)))
    finally:
        shutil.rmtree(working_dir)


if __name__ == '__main__':
    main(sys.argv[1:])
