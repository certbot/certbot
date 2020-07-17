#!/usr/bin/env python3
import argparse
import glob
import datetime
from multiprocessing import Pool, Process, Manager
import re
import subprocess
import sys
import time
from os.path import join, realpath, dirname, basename


CERTBOT_DIR = dirname(dirname(dirname(realpath(__file__))))
PLUGINS = [basename(path) for path in glob.glob(join(CERTBOT_DIR, 'certbot-dns-*'))]


def _build_remote_snap(target, archs, status):
    status[target] = {arch: '...' for arch in archs}

    if target == 'certbot':
        workspace = CERTBOT_DIR
    else:
        workspace = join(CERTBOT_DIR, target)
        subprocess.check_output(
            ('"{0}" tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt '
             '| grep -v python-augeas > "{1}/snap-constraints.txt"').format(sys.executable, workspace),
            shell=True, cwd=CERTBOT_DIR)

    process = subprocess.Popen([
        'snapcraft', 'remote-build', '--launchpad-accept-public-upload', '--recover', '--build-on', ','.join(archs)
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, cwd=workspace)

    line = process.stdout.readline()
    while line:
        _extract_remote_state(target, line, status)
        line = process.stdout.readline()

    return {target: workspace}


def _extract_remote_state(project, output, status):
    match = re.match(r'^.*arch=(\w+)\s+state=([\w ]+).*$', output)
    if match:
        arch = match.group(1)
        state = status[project]
        state[arch] = match.group(2)

        status[project] = state


def _dump_remote_status(archs, status, final=False):
    while True:
        if final:
            print('Results for remote build finished at {0}'.format(datetime.datetime.now()))
        else:
            print('Remote build status at {0}'.format(datetime.datetime.now()))
        print(' project                    {0}'.format(''.join('| {0}                       '.format(arch)
                                                               for arch in archs)))
        print('----------------------------{0}'.format('+-----------------------------' * len(archs)))
        for project, states in sorted(status.items()):
            print(' {0} {1}'.format(
                project + ' ' * (25 - len(project)),
                ''.join(' | {0}'.format(states[arch] + ' ' * (27 - len(states[arch]))) for arch in archs)))
        print('----------------------------{0}'.format('+-----------------------------' * len(archs)))
        print()

        sys.stdout.flush()

        time.sleep(10)


def _dump_remote_results(targets, archs, status, workspaces):
    failures = False
    for target in targets:
        for arch in archs:
            result = status[target][arch]

            if result != 'Successfully built':
                failures = True

                with open(join(workspaces[target], '{0}_{1}.txt'.format(target, arch))) as file_h:
                    build_output = file_h.read()

                print('Output for failed build target={0} arch={1}'.format(target, arch))
                print('-------------------------------------------')
                print(build_output)
                print('-------------------------------------------')
                print()

    if not failures:
        print('All builds succeeded.')
    else:
        print('Some builds failed.')

    return failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('targets', nargs='+', choices=['ALL', 'DNS_PLUGINS', 'certbot', *PLUGINS],
                        help='the list of snaps to build')
    parser.add_argument('--archs', nargs='+', choices=['amd64', 'arm64', 'armhf'], default='amd64',
                        help='the architectures for which snaps are built')
    args = parser.parse_args()

    archs = set(args.archs)
    targets = set(args.targets)

    if 'ALL' in targets:
        targets.remove('ALL')
        targets.update(['certbot', 'DNS_PLUGINS'])

    if 'DNS_PLUGINS' in targets:
        targets.remove('DNS_PLUGINS')
        targets.update(PLUGINS)

    status = Manager().dict()

    state_process = Process(target=_dump_remote_status, args=(archs, status,))
    state_process.start()

    pool = Pool(processes=len(targets))
    async_results = [pool.apply_async(_build_remote_snap, (target, archs, status)) for target in targets]

    workspaces = {}
    for async_result in async_results:
        workspaces.update(async_result.get())

    state_process.terminate()

    failures = _dump_remote_results(targets, archs, status, workspaces)
    _dump_remote_status(archs, status, final=True)

    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
