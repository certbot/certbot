#!/usr/bin/env python3
import argparse
import curses
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


def _build_snap(target, archs, status):
    status[target] = {}
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
        _extract_state(target, line, status)
        line = process.stdout.readline()

    return {target: workspace}


def _extract_state(project, output, status):
    match = re.match(r'^.*arch=(\w+)\s+state=([\w ]+).*$', output)
    if match:
        arch = match.group(1)
        state_str = match.group(2)
        state = status[project]
        if state_str == 'Successfully built':
            state[arch] = 'S'
        elif state_str == 'Failed to build':
            state[arch] = 'F'
        elif state_str == 'Uploading build':
            state[arch] = 'U'
        elif state_str == 'Currently building':
            state[arch] = 'B'
        elif state_str == 'Needs building':
            state[arch] = 'W'

        status[project] = state


def _dump_status(status):
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()

    try:
        while True:
            stdscr.addstr(0, 0, 'Build status at {0}'.format(datetime.datetime.now()))
            stdscr.addstr(1, 0, 'W = wait, B = building, U = uploading, F = fail, S = success')
            stdscr.addstr(2, 0, ' project                     amd64   arm64   armhf ')
            stdscr.addstr(3, 0, '---------------------------+-------+-------+-------')
            idx = 4
            for project, states in status.items():
                stdscr.addstr(idx, 0, ' {0} |   {1}   |   {2}   |   {3}   '.format(
                    project + ' ' * (25 - len(project)), states.get('arm64', 'W'),
                    states.get('arm64', 'W'), states.get('armhf', 'W')))
                idx = idx + 1

            stdscr.refresh()
            time.sleep(1)
    finally:
        curses.echo()
        curses.nocbreak()
        curses.endwin()


def _dump_results(targets, archs, status, workspaces):
    failures = False
    for target in targets:
        for arch in archs:
            result = status[target][arch]

            if result == 'F':
                failures = True

                with open(join(workspaces[target], '{0}_{1}.txt'.format(target, arch))) as file_h:
                    build_output = file_h.read()

                print('Output for failed build target={0} arch={1}'.format(target, arch))
                print('-------------------------------------------')
                print(build_output)
                print('-------------------------------------------')

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

    state_process = Process(target=_dump_status, args=(status,))
    state_process.start()

    pool = Pool(processes=len(targets))
    async_results = [pool.apply_async(_build_snap, (target, archs, status)) for target in targets]

    workspaces = {}
    for async_result in async_results:
        workspaces.update(async_result.get())

    state_process.terminate()

    failures = _dump_results(targets, archs, status, workspaces)

    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
