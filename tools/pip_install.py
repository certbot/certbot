#!/usr/bin/env python
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, a combination of tools/oldest_constraints.txt and
# tools/dev_constraints.txt is used, otherwise, tools/requirements.txt is used.

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


def certbot_oldest_processing(tools_path, constraints_path):
    # The order of the files in this list matters as files specified later can
    # override the pinnings found in earlier files.
    pinning_files = [os.path.join(tools_path, 'dev_constraints.txt'),
                     os.path.join(tools_path, 'oldest_constraints.txt')]
    with open(constraints_path, 'w') as fd:
        fd.write(merge_module.main(*pinning_files))


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
            if os.environ.get('CERTBOT_OLDEST') == '1':
                certbot_oldest_processing(tools_path, constraints_path)
            else:
                certbot_normal_processing(tools_path, constraints_path)

            env = os.environ.copy()
            env["PIP_CONSTRAINT"] = constraints_path

            pip_install_with_print(' '.join(args), env=env)


if __name__ == '__main__':
    main(sys.argv[1:])
