#!/usr/bin/env python3
import argparse
import glob
import datetime
from multiprocessing import Pool, Process, Manager, Event
import re
import subprocess
import sys
import tempfile
from os.path import join, realpath, dirname, basename, exists


CERTBOT_DIR = dirname(dirname(dirname(realpath(__file__))))
PLUGINS = [basename(path) for path in glob.glob(join(CERTBOT_DIR, 'certbot-dns-*'))]


def _execute_build(target, archs, status, workspace):
    process = subprocess.Popen([
        'snapcraft', 'remote-build', '--launchpad-accept-public-upload', '--recover', '--build-on', ','.join(archs)
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, cwd=workspace)

    process_output = []
    for line in process.stdout:
        process_output.append(line)
        _extract_state(target, line, status)

    return process.wait(), process_output


def _build_snap(target, archs, status, lock):
    status[target] = {arch: '...' for arch in archs}

    if target == 'certbot':
        workspace = CERTBOT_DIR
    else:
        workspace = join(CERTBOT_DIR, target)
        with tempfile.NamedTemporaryFile() as f:
            subprocess.check_output(
                ('"{0}" tools/strip_hashes.py letsencrypt-auto-source/pieces/dependency-requirements.txt '
                 '| grep -v python-augeas > "{1}"').format(sys.executable, f.name),
            shell=True, cwd=CERTBOT_DIR)
            subprocess.check_output(
                ('"{0}" tools/merge_requirements.py tools/dev_constraints.txt '
                 '"{1}" > "{2}/snap-constraints.txt"').format(sys.executable, f.name, workspace),
            shell=True, cwd=CERTBOT_DIR)

    retry = 3
    while retry:
        exit_code, process_output = _execute_build(target, archs, status, workspace)

        print(f'Build {target} for {",".join(archs)} (attempt {4-retry}/3) ended with exit code {exit_code}.')
        sys.stdout.flush()

        with lock:
            dump_output = exit_code != 0
            failed_archs = [arch for arch in archs if status[target][arch] == 'Failed to build']
            if exit_code == 0 and not failed_archs:
                # We expect to have all target snaps available, or something bad happened.
                snaps_list = glob.glob(join(workspace, '*.snap'))
                if not len(snaps_list) == len(archs):
                    print(f'Some of the expected snaps for a successful build are missing (current list: {snaps_list}).')
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

        # Retry the remote build if it has been interrupted (non zero status code) or if some builds have failed.
        retry = retry - 1

    return {target: workspace}


def _extract_state(project, output, status):
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


def _dump_status_helper(archs, status):
    headers = ['project', *archs]
    print(''.join(f'| {item:<25}' for item in headers))
    print(f'|{"-" * 26}' * len(headers))
    for project, states in sorted(status.items()):
        print(''.join(f'| {item:<25}' for item in [project, *[states[arch] for arch in archs]]))
    print(f'|{"-" * 26}' * len(headers))
    print()

    sys.stdout.flush()


def _dump_status(archs, status, stop_event):
    while not stop_event.wait(10):
        print('Remote build status at {0}'.format(datetime.datetime.now()))
        _dump_status_helper(archs, status)


def _dump_status_final(archs, status):
    print('Results for remote build finished at {0}'.format(datetime.datetime.now()))
    _dump_status_helper(archs, status)


def _dump_results(targets, archs, status, workspaces):
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
    parser.add_argument('--archs', nargs='+', choices=['amd64', 'arm64', 'armhf'], default=['amd64'],
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

    print('Start remote snap builds...')
    print(f' - archs: {", ".join(archs)}')
    print(f' - projects: {", ".join(sorted(targets))}')
    print()

    with Manager() as manager, Pool(processes=len(targets)) as pool:
        status = manager.dict()
        lock = manager.Lock()

        stop_event = Event()
        state_process = Process(target=_dump_status, args=(archs, status, stop_event))
        state_process.start()

        async_results = [pool.apply_async(_build_snap, (target, archs, status, lock)) for target in targets]

        workspaces = {}
        for async_result in async_results:
            workspaces.update(async_result.get())

        stop_event.set()
        state_process.join()

        failures = _dump_results(targets, archs, status, workspaces)
        _dump_status_final(archs, status)

        return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
