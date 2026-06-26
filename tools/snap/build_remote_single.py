#!/usr/bin/env python3
import argparse
import functools
import glob
import os
from os.path import basename
from os.path import dirname
from os.path import join
from os.path import realpath
import random
import re
import string
import subprocess
import sys
import tempfile
from typing import List
from typing import Tuple

CERTBOT_DIR = dirname(dirname(dirname(realpath(__file__))))
PLUGINS = [basename(path) for path in glob.glob(join(CERTBOT_DIR, 'certbot-dns-*'))]


# In Python, stdout and stderr are buffered in each process by default. When
# printing output from multiple processes, this can cause delays in printing
# output with lines from different processes being interleaved depending
# on when the output for that process is flushed. To prevent this, we override
# print so that it always flushes its output. Disabling output buffering can
# also be done through command line flags or environment variables set when the
# Python process starts, but this approach was taken instead to ensure
# consistent behavior regardless of how the script is invoked.
print = functools.partial(print, flush=True)


def _execute_build(
        target: str, arch: str,
        workspace: str) -> Tuple[int, List[str], str]:
    # The implementation of remote-build recovery has changed over time.
    # Currently, you cannot set a build-id, and the build-id is instead derived
    # from a hash of the contents of the files in the directory:
    # https://github.com/canonical/craft-application/blob/5b09ab3d9152a2b61ffcdf57691289023ed6ba26/craft_application/remote/utils.py#L64
    #
    # We want a unique build ID so a fresh build is started for each run instead
    # of potentially reusing an old build. See https://github.com/certbot/certbot/pull/8719
    # and https://github.com/snapcore/snapcraft/pull/3554 for more info.
    #
    # In the hope that one day you can again set a build ID, we will modify
    # the directory by creating a file containing a build ID that conforms
    # to the shape of snapcraft's build ID: using a MD5 hash represented as a
    # 32 character hex string (we use a larger character set).

    status: str = "..."

    random_string = ''.join(random.choice(string.ascii_lowercase + string.digits)
                            for _ in range(32))
    # place random string in build_id file inside `workspace` directory
    with open(join(workspace, 'build_id'), 'w') as build_id_file:
        build_id_file.write(random_string)

    with tempfile.TemporaryDirectory() as tempdir:
        environ = os.environ.copy()
        environ['XDG_CACHE_HOME'] = tempdir
        process = subprocess.Popen([
            'snapcraft', 'remote-build', '--launchpad-accept-public-upload',
            '--build-for', arch],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, env=environ, cwd=workspace, bufsize=1)

    killed = False
    process_output: List[str] = []
    for line in process.stdout:
        print(line.rstrip())
        process_output.append(line.rstrip())
        status = _extract_state(target, line, status)

        if not killed and status == 'Chroot problem':
            # On this error the snapcraft process hangs. Let's finish it.
            #
            # killed is used to stop us from executing this code path
            # multiple times per build that encounters "Chroot problem".
            print('Chroot problem encountered for build '
                  f'{target} for {arch}.\n'
                  'Launchpad seems to be unable to recover from this '
                  'state so we are terminating the build.')
            process.kill()
            killed = True

    process_state = process.wait()

    return process_state, process_output, status


def _extract_state(project: str, output: str, state: str) -> str:
    # This output may change, and is set by
    # https://github.com/canonical/snapcraft/blob/8ab7fd0c8a1d3f13045bec41a6e0158c063faa9b/snapcraft/commands/remote.py#L218
    if "Starting new build" in output:
        state = "Starting new build"

    match = re.match(r'^(\w+): (\w+)$', output)
    if match:
        state = match.group(1)

    return state


def build_snap(target: str, arch: str) -> None:
    if target == 'certbot':
        workspace = CERTBOT_DIR
    else:
        workspace = join(CERTBOT_DIR, target)
        # Init and commit git repo in workspace. This is necessary starting in core24
        # as "Projects must be at the top level of a git repository"
        # https://snapcraft.io/docs/migrate-core24#remote-build
        subprocess.run(['git', 'init'], capture_output=True, check=True, cwd=workspace)
        subprocess.run(['git', 'add', '-A'], capture_output=True, check=True, cwd=workspace)
        subprocess.run(['git', 'commit', '-m', 'init'], capture_output=True, check=True, cwd=workspace)

    exit_code, process_output, status = _execute_build(target, arch, workspace)
    print(f'Build {target} for {arch} ended with '
          f'exit code {exit_code}.')

    # This output may change, and is set by
    # https://github.com/canonical/snapcraft/blob/8ab7fd0c8a1d3f13045bec41a6e0158c063faa9b/snapcraft/commands/remote.py#L278
    failed = status != 'Succeeded'

    # If the command failed, let's try to print all the output about the problem
    # that we can.
    failed = exit_code != 0 or failed

    # Check that snap file exists
    # We expect to have the target snap available, or something bad happened.
    if not failed:
        snap_path_list = glob.glob(join(workspace, f'{target}_*_{arch}.snap'))
        if not len(snap_path_list) == 1:
            print('The expected snap is missing.')
            failed = True

    # Check if the snap file just contains html
    if not failed:
        with open(snap_path_list[0], 'r') as f:
            try:
                first_line = f.readline().rstrip()
            except UnicodeDecodeError:
                first_line = ''
            if first_line == "<!DOCTYPE html>":
                failed = True
                print(f'The {target} {arch} snap file contains html instead of a snap')

    if failed:
        print('Dumping snapcraft remote-build logs:')
        log_location = _extract_log_location(process_output[-1])
        _dump_failed_build_logs(log_location)
        print('Build failed.')
        raise ValueError("There were failures during the build!")
    else:
        print('Build succeeded.')


def _extract_log_location(line: str) -> str:
    print(f'Final line: {line}') # for testing, should be removed
    result = ""
    match = re.match(r"^Full execution log: '(.+)'$", line)

    if match:
        result = match.group(1)
    print(f'Log location: {result}') # for testing, should be removed
    return result


def _dump_failed_build_logs(build_output_path: str) -> None:
    if not build_output_path:
        build_output = 'Log location not extracted from output.'
    else:
        with open(build_output_path) as file_h:
            build_output = file_h.read()

    print('Output for failed build')
    print('-------------------------------------------')
    print(build_output)
    print('-------------------------------------------')
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', choices=['certbot', *PLUGINS],
                        help='the snap to build')
    parser.add_argument('--arch', choices=['amd64', 'arm64', 'armhf'],
                        default='amd64', help='the architecture for which snap is built')
    args = parser.parse_args()

    arch = args.arch
    target = args.target

    # If we're building anything other than just Certbot, we need to
    # generate the snapcraft files for the DNS plugins.
    if target != 'certbot':
        subprocess.run(['tools/snap/generate_dnsplugins_all.sh'],
                       check=True, cwd=CERTBOT_DIR)

    print('Start remote snap build...')
    print(f' - arch: {arch}')
    print(f' - project: {target}')
    print()

    build_snap(target, arch)


if __name__ == '__main__':
    sys.exit(main())
