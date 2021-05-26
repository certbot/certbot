#!/usr/bin/env python
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, a combination of tools/oldest_constraints.txt,
# tools/dev_constraints.txt, and local-oldest-requirements.txt contained in the
# top level of the package's directory is used, otherwise,
# tools/requirements.txt is used. If CERTBOT_OLDEST is set, this script must
# be run with `-e <package-name>` and no other arguments.

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


def certbot_oldest_processing(tools_path, args, constraints_path):
    if args[0] != '-e' or len(args) != 2:
        raise ValueError('When CERTBOT_OLDEST is set, this script must be run '
                         'with a single -e <path> argument.')
    # remove any extras such as [dev]
    pkg_dir = re.sub(r'\[\w+\]', '', args[1])
    # The order of the files in this list matters as files specified later can
    # override the pinnings found in earlier files.
    pinning_files = [os.path.join(tools_path, 'dev_constraints.txt'),
                     os.path.join(tools_path, 'oldest_constraints.txt')]
    requirements = os.path.join(pkg_dir, 'local-oldest-requirements.txt')
    # packages like acme don't have any local oldest requirements
    if os.path.isfile(requirements):
        # We add requirements to the end of the list so it can override
        # anything that it needs to.
        pinning_files.append(requirements)
    else:
        requirements = None
    with open(constraints_path, 'w') as fd:
        fd.write(merge_module.main(*pinning_files))
    return requirements


def certbot_normal_processing(tools_path, constraints_path):
    repo_path = os.path.dirname(tools_path)
    requirements = os.path.normpath(os.path.join(
        repo_path, 'tools/requirements.txt'))
    shutil.copy(requirements, constraints_path)


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
        if os.environ.get('CERTBOT_NO_PIN') == '1':
            # With unpinned dependencies, there is no constraint
            pip_install_with_print(' '.join(args))
        else:
            # Otherwise, we merge requirements to build the constraints and pin dependencies
            constraints_path = os.path.join(working_dir, 'constraints.txt')
            requirements = None
            if os.environ.get('CERTBOT_OLDEST') == '1':
                requirements = certbot_oldest_processing(tools_path, args, constraints_path)
            else:
                certbot_normal_processing(tools_path, constraints_path)

            env = os.environ.copy()
            env["PIP_CONSTRAINT"] = constraints_path

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

            print(' '.join(args))
            pip_install_with_print(' '.join(args), env=env)


if __name__ == '__main__':
    main(sys.argv[1:])
