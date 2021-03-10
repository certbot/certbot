#!/usr/bin/env python3
import argparse
import datetime
import glob
from multiprocessing import Manager
from multiprocessing import Pool
from multiprocessing import Process
from multiprocessing.managers import SyncManager
import os
from os.path import basename
from os.path import dirname
from os.path import exists
from os.path import join
from os.path import realpath
import re
import subprocess
import sys
import tempfile
from threading import Lock
import time
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

CERTBOT_DIR = dirname(dirname(dirname(realpath(__file__))))
PLUGINS = [basename(path) for path in glob.glob(join(CERTBOT_DIR, 'certbot-dns-*'))]


def _execute_build(
        target: str, archs: Set[str], status: Dict[str, Dict[str, str]],
        workspace: str) -> Tuple[int, List[str]]:

    with tempfile.TemporaryDirectory() as tempdir:
        environ = os.environ.copy()
        environ['XDG_CACHE_HOME'] = tempdir
        process = subprocess.Popen([
            'snapcraft', 'remote-build', '--launchpad-accept-public-upload', '--recover',
            '--build-on', ','.join(archs)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, env=environ, cwd=workspace)

    process_output: List[str] = []
    for line in process.stdout:
        process_output.append(line)
        _extract_state(target, line, status)

        if any(state for state in status[target].values() if state == 'Chroot problem'):
            # On this error the snapcraft process stales. Let's finish it.
            process.kill()

    return process.wait(), process_output


def _build_snap(
        target: str, archs: Set[str], status: Dict[str, Dict[str, str]],
        running: Dict[str, bool], lock: Lock) -> Dict[str, str]:
    status[target] = {arch: '...' for arch in archs}

    if target == 'certbot':
        workspace = CERTBOT_DIR
    else:
        workspace = join(CERTBOT_DIR, target)

    retry = 3
    while retry:
        exit_code, process_output = _execute_build(target, archs, status, workspace)

        print(f'Build {target} for {",".join(archs)} (attempt {4-retry}/3) ended with '
              f'exit code {exit_code}.')
        sys.stdout.flush()

        with lock:
            dump_output = exit_code != 0
            failed_archs = [arch for arch in archs if status[target][arch] != 'Successfully built']
            if any(arch for arch in archs if status[target][arch] == 'Chroot problem'):
                print('Some builds failed with the status "Chroot problem".')
                print('This status is known to make any future build fail until either '
                      'the source code changes or the build on Launchpad is deleted.')
                print('Please fix the build appropriately before trying a new one.')
                # It is useless to retry in this situation.
                retry = 0
            if exit_code == 0 and not failed_archs:
                # We expect to have all target snaps available, or something bad happened.
                snaps_list = glob.glob(join(workspace, '*.snap'))
                if not len(snaps_list) == len(archs):
                    print('Some of the expected snaps for a successful build are missing '
                          f'(current list: {snaps_list}).')
                    dump_output = True
                else:
                    break
            if failed_archs:
                # We expect each failed build to have a log file, or something bad happened.
                for arch in failed_archs:
                    if not exists(join(workspace, f'{target}_{arch}.txt')):
                        dump_output = True
                        print(f'Missing output on a failed build {target} for {arch}.')
            if dump_output:
                print(f'Dumping snapcraft remote-build output build for {target}:')
                print('\n'.join(process_output))

        # Retry the remote build if it has been interrupted (non zero status code)
        # or if some builds have failed.
        retry = retry - 1

    running[target] = False

    return {target: workspace}


def _extract_state(project: str, output: str, status: Dict[str, Dict[str, str]]) -> None:
    match = re.match(r'^.*arch=(\w+)\s+state=([\w ]+).*$', output)
    if match:
        arch = match.group(1)
        state = status[project]
        state[arch] = match.group(2)

        # You need to reassign the value of status[project] here (rather than doing
        # something like status[project][arch] = match.group(2)) for the state change
        # to propagate to other processes. See
        # https://docs.python.org/3.8/library/multiprocessing.html#proxy-objects for
        # more info.
        status[project] = state


def _dump_status_helper(archs: Set[str], status: Dict[str, Dict[str, str]]) -> None:
    headers = ['project', *archs]
    print(''.join(f'| {item:<25}' for item in headers))
    print(f'|{"-" * 26}' * len(headers))
    for project, states in sorted(status.items()):
        print(''.join(f'| {item:<25}' for item in [project, *[states[arch] for arch in archs]]))
    print(f'|{"-" * 26}' * len(headers))
    print()

    sys.stdout.flush()


def _dump_status(
        archs: Set[str], status: Dict[str, Dict[str, str]],
        running: Dict[str, bool]) -> None:
    while any(running.values()):
        print(f'Remote build status at {datetime.datetime.now()}')
        _dump_status_helper(archs, status)
        time.sleep(10)


def _dump_results(
        targets: Set[str], archs: Set[str], status: Dict[str, Dict[str, str]],
        workspaces: Dict[str, str]) -> bool:
    failures = False
    for target in targets:
        for arch in archs:
            result = status[target][arch]

            if result != 'Successfully built':
                failures = True

                build_output_path = join(workspaces[target], f'{target}_{arch}.txt')
                if not exists(build_output_path):
                    build_output = f'No output has been dumped by snapcraft remote-build.'
                else:
                    with open(join(workspaces[target], f'{target}_{arch}.txt')) as file_h:
                        build_output = file_h.read()

                print(f'Output for failed build target={target} arch={arch}')
                print('-------------------------------------------')
                print(build_output)
                print('-------------------------------------------')
                print()

    if not failures:
        print('All builds succeeded.')
    else:
        print('Some builds failed.')

    print()
    print(f'Results for remote build finished at {datetime.datetime.now()}')
    _dump_status_helper(archs, status)

    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('targets', nargs='+', choices=['ALL', 'DNS_PLUGINS', 'certbot', *PLUGINS],
                        help='the list of snaps to build')
    parser.add_argument('--archs', nargs='+', choices=['amd64', 'arm64', 'armhf'],
                        default=['amd64'], help='the architectures for which snaps are built')
    parser.add_argument('--timeout', type=int, default=None,
                        help='build process will fail after the provided timeout (in seconds)')
    args = parser.parse_args()

    archs = set(args.archs)
    targets = set(args.targets)

    if 'ALL' in targets:
        targets.remove('ALL')
        targets.update(['certbot', 'DNS_PLUGINS'])

    if 'DNS_PLUGINS' in targets:
        targets.remove('DNS_PLUGINS')
        targets.update(PLUGINS)

    # If we're building anything other than just Certbot, we need to
    # generate the snapcraft files for the DNS plugins.
    if targets != {'certbot'}:
        subprocess.run(['tools/snap/generate_dnsplugins_all.sh'],
                       check=True, cwd=CERTBOT_DIR)

    print('Start remote snap builds...')
    print(f' - archs: {", ".join(archs)}')
    print(f' - projects: {", ".join(sorted(targets))}')
    print()

    manager: SyncManager = Manager()
    pool = Pool(processes=len(targets))
    with manager, pool:
        status: Dict[str, Dict[str, str]] = manager.dict()
        running = manager.dict({target: True for target in targets})
        lock = manager.Lock()

        async_results = [pool.apply_async(_build_snap, (target, archs, status, running, lock))
                         for target in targets]

        process = Process(target=_dump_status, args=(archs, status, running))
        process.start()

        try:
            process.join(args.timeout)

            if process.is_alive():
                raise ValueError(f"Timeout out reached ({args.timeout} seconds) during the build!")

            workspaces = {}
            for async_result in async_results:
                workspaces.update(async_result.get())

            if _dump_results(targets, archs, status, workspaces):
                raise ValueError("There were failures during the build!")
        finally:
            process.terminate()


if __name__ == '__main__':
    sys.exit(main())
