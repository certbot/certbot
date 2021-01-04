#!/usr/bin/env python
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, a combination of tools/oldest_constraints.txt,
# tools/dev_constraints.txt, and local-oldest-requirements.txt contained in the
# top level of the package's directory is used, otherwise, a combination of
# certbot-auto's requirements file and tools/dev_constraints.txt is used. The
# other file always takes precedence over tools/dev_constraints.txt. If
# CERTBOT_OLDEST is set, this script must be run with `-e <package-name>` and
# no other arguments.

from __future__ import absolute_import
from __future__ import print_function

import contextlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

import merge_requirements as merge_module
import readlink
import strip_hashes


# Once this code doesn't need to support Python 2, we can simply use
# tempfile.TemporaryDirectory.
@contextlib.contextmanager
def temporary_directory():
    dirpath = tempfile.mkdtemp()
    try:
        yield dirpath
    finally:
        shutil.rmtree(dirpath)


def find_tools_path():
    return os.path.dirname(readlink.main(__file__))


def certbot_oldest_processing(tools_path, args, test_constraints):
    if args[0] != '-e' or len(args) != 2:
        raise ValueError('When CERTBOT_OLDEST is set, this script must be run '
                         'with a single -e <path> argument.')
    # remove any extras such as [dev]
    pkg_dir = re.sub(r'\[\w+\]', '', args[1])
    requirements = os.path.join(pkg_dir, 'local-oldest-requirements.txt')
    shutil.copy(os.path.join(tools_path, 'oldest_constraints.txt'), test_constraints)
    # packages like acme don't have any local oldest requirements
    if not os.path.isfile(requirements):
        return None

    return requirements


def certbot_normal_processing(tools_path, test_constraints):
    repo_path = os.path.dirname(tools_path)
    certbot_requirements = os.path.normpath(os.path.join(
        repo_path, 'letsencrypt-auto-source/pieces/dependency-requirements.txt'))
    with open(certbot_requirements, 'r') as fd:
        certbot_reqs = fd.readlines()
    with open(os.path.join(tools_path, 'pipstrap_constraints.txt'), 'r') as fd:
        pipstrap_reqs = fd.readlines()
    with open(test_constraints, 'w') as fd:
        data_certbot = "\n".join(strip_hashes.process_entries(certbot_reqs))
        data_pipstrap = "\n".join(strip_hashes.process_entries(pipstrap_reqs))
        data = "\n".join([data_certbot, data_pipstrap])
        fd.write(data)


def merge_requirements(tools_path, requirements, test_constraints, all_constraints):
    # Order of the files in the merge function matters.
    # Indeed version retained for a given package will be the last version
    # found when following all requirements in the given order.
    # Here is the order by increasing priority:
    # 1) The general development constraints (tools/dev_constraints.txt)
    # 2) The general tests constraints (oldest_requirements.txt or
    #    certbot-auto's dependency-requirements.txt + pipstrap's constraints
    #    for the normal processing)
    # 3) The local requirement file, typically local-oldest-requirement in oldest tests
    files = [os.path.join(tools_path, 'dev_constraints.txt'), test_constraints]
    if requirements:
        files.append(requirements)
    merged_requirements = merge_module.main(*files)
    with open(all_constraints, 'w') as fd:
        fd.write(merged_requirements)


def call_with_print(command, env=None):
    if not env:
        env = os.environ
    print(command)
    subprocess.check_call(command, shell=True, env=env)


def pip_install_with_print(args_str, env=None):
    if not env:
        env = os.environ
    command = ['"', sys.executable, '" -m pip install --disable-pip-version-check ', args_str]
    call_with_print(''.join(command), env=env)


def main(args):
    tools_path = find_tools_path()

    with temporary_directory() as working_dir:
        test_constraints = os.path.join(working_dir, 'test_constraints.txt')
        all_constraints = os.path.join(working_dir, 'all_constraints.txt')

        if os.environ.get('CERTBOT_NO_PIN') == '1':
            # With unpinned dependencies, there is no constraint
            pip_install_with_print(' '.join(args))
        else:
            # Otherwise, we merge requirements to build the constraints and pin dependencies
            requirements = None
            if os.environ.get('CERTBOT_OLDEST') == '1':
                requirements = certbot_oldest_processing(tools_path, args, test_constraints)
            else:
                certbot_normal_processing(tools_path, test_constraints)

            env = os.environ.copy()
            env["PIP_CONSTRAINT"] = all_constraints

            merge_requirements(tools_path, requirements, test_constraints, all_constraints)
            if requirements:  # This branch is executed during the oldest tests
                # First step, install the transitive dependencies of oldest requirements
                # in respect with oldest constraints.
                pip_install_with_print('--requirement "{0}"'.format(requirements),
                                       env=env)
                # Second step, ensure that oldest requirements themselves are effectively
                # installed using --force-reinstall, and avoid corner cases like the one described
                # in https://github.com/certbot/certbot/issues/7014.
                pip_install_with_print('--force-reinstall --no-deps --requirement "{0}"'
                                       .format(requirements))

            pip_install_with_print(' '.join(args), env=env)


if __name__ == '__main__':
    main(sys.argv[1:])
