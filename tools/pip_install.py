#!/usr/bin/env python
# pip installs packages using pinned package versions. If CERTBOT_OLDEST is set
# to 1, tools/oldest_constraints.txt is used, otherwise, tools/requirements.txt
# is used. Before installing the requested packages, core Python packaging
# tools like pip, setuptools, and wheel are updated to pinned versions to
# increase stability of the install.

from __future__ import absolute_import
from __future__ import print_function

import contextlib
import os
import subprocess
import sys
import tempfile


def find_tools_path():
    return os.path.dirname(os.path.realpath(__file__))


def call_with_print(command, env):
    assert env is not None
    print(command)
    subprocess.check_call(command, shell=True, env=env)


def pip_install_with_print(args_str, env):
    command = ['"', sys.executable, '" -m pip install --disable-pip-version-check ', args_str]
    call_with_print(''.join(command), env=env)


@contextlib.contextmanager
def modified_environ():
    tools_path = find_tools_path()

    with tempfile.TemporaryDirectory() as working_dir:
        repo_path = os.path.dirname(tools_path)
        if os.environ.get('CERTBOT_OLDEST') == '1':
            constraints_path = os.path.normpath(os.path.join(
                repo_path, 'tools', 'oldest_constraints.txt'))
        else:
            constraints_path = os.path.normpath(os.path.join(
                repo_path, 'tools', 'requirements.txt'))

        env = os.environ.copy()
        # We set constraints for pip using an environment variable so that they
        # are also used when installing build dependencies. See
        # https://github.com/certbot/certbot/pull/8443 for more info.
        env["PIP_CONSTRAINT"] = constraints_path
        yield env


def pipstrap(env=None):
    if env is None:
        context_manager = modified_environ()
    else:
        context_manager = contextlib.nullcontext(env)
    with context_manager as env:
        pip_install_with_print('pip setuptools wheel', env=env)


def main(args):
    with modified_environ() as env:
        pipstrap(env)
        pip_install_with_print(' '.join(args), env=env)


if __name__ == '__main__':
    main(sys.argv[1:])
