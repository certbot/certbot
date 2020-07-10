#!/usr/bin/env python3
import argparse
import glob
import multiprocessing
import re
import subprocess
import sys
from os.path import join, realpath, dirname, basename, exists


CERTBOT_DIR = dirname(dirname(dirname(realpath(__file__))))
PLUGINS = [basename(path) for path in glob.glob(join(CERTBOT_DIR, 'certbot-dns-*'))]


def _build_snap(target, archs):
    if target == 'certbot':
        workspace = CERTBOT_DIR
    else:
        workspace = join(CERTBOT_DIR, target)
        subprocess.check_output(
            ('"{0}" tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt '
             '| grep -v python-augeas > "{1}/snap-constraints.txt"').format(sys.executable, workspace),
            shell=True, cwd=workspace)

    try:
        subprocess.check_call([
            'snapcraft', 'remote-build', '--launchpad-accept-public-upload',
            '--build-on', ','.join(archs)
        ], universal_newlines=True, cwd=workspace)
    except subprocess.CalledProcessError as e:
        # Will be handled after
        pass

    status = {}

    for arch in archs:
        status[arch] = None
        build_file = join(workspace, '{0}_{1}.txt'.format(target, arch))
        if build_file:
            with open(build_file) as file_h:
                build_output = file_h.read()

            if not re.search(r'Snapped {0}_.*_{1}\.snap'.format(target, arch), build_output):
                status[arch] = build_output

    return {target: status}


def _dump_results(targets, archs, results):
    failures = False
    for target in targets:
        for arch in archs:
            build_output = results[target][arch]
            if build_output:
                failures = True
                print('Output for failed build target={0} arch={1}'.format(target, arch))
                print('-------------------------------------------')
                print(build_output)
                print('-------------------------------------------')

    print('Build summary')
    print('=============')
    targets = list(targets)
    targets.sort()
    for target in targets:
        print('Builds for target={0}: {1}'.format(
            target,
            ', '.join([
                'arch={0} ({1})'.format(arch, 'success' if not results[target][arch] else 'failure')
                for arch in archs
            ])
        ))

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

    pool = multiprocessing.Pool(processes=len(targets))
    async_results = [pool.apply_async(_build_snap, (target, archs)) for target in targets]

    results = {}

    for async_result in async_results:
        results.update(async_result.get())

    failures = _dump_results(targets, archs, results)

    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
