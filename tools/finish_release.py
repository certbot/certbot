#!/usr/bin/env python
"""
Post-release script to publish artifacts created from GitHub Actions.

This currently includes:

* Moving snaps from the beta channel to the stable channel

Setup:
 - Install the snapcraft command line tool and log in to a privileged account.
   - https://snapcraft.io/docs/installing-snapcraft
   - Use the command `snapcraft login` to log in.

Run:

python tools/finish_release.py

Testing:

This script can be safely run between releases. When this is done, the script
should execute successfully.

"""

import argparse
import glob
import os.path
import re
import subprocess
import sys

# Path to the root directory of the Certbot repository containing this script
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# This list contains the names of all Certbot DNS plugins. We used to have a
# CloudXNS plugin and since it's possible devs still have that directory
# locally, we filter it out here. If it's included in this list, this script
# will crash later when it fails to find a CloudXNS snap on the snap store with
# the current version since we no longer build it.
PLUGIN_SNAPS = [os.path.basename(path)
                for path in glob.glob(os.path.join(REPO_ROOT, 'certbot-dns-*'))
                if not path.endswith('certbot-dns-cloudxns')]
# This list contains the name of all Certbot snaps that should be published to
# the stable channel.
ALL_SNAPS = ['certbot'] + PLUGIN_SNAPS
# This is the count of the architectures currently supported by our snaps used
# for sanity checking.
SNAP_ARCH_COUNT = 3


def parse_args(args):
    """Parse command line arguments.

    :param args: command line arguments with the program name removed. This is
        usually taken from sys.argv[1:].
    :type args: `list` of `str`

    :returns: parsed arguments
    :rtype: argparse.Namespace

    """
    # Use the file's docstring for the help text and don't let argparse reformat it.
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    return parser.parse_args(args)


def assert_logged_into_snapcraft():
    """Confirms that snapcraft is logged in to an account.

    :raises SystemExit: if the command snapcraft is unavailable or it
        isn't logged into an account

    """
    cmd = 'snapcraft whoami'.split()
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, universal_newlines=True)
    except (subprocess.CalledProcessError, OSError):
        print("Please make sure that the command line tool snapcraft is")
        print("installed and that you have logged in to an account by running")
        print("'snapcraft login'. If that fails, your credentials may have expired")
        print("and you should run `snapcraft logout` followed by 'snapcraft login'.")
        sys.exit(1)


def get_snap_revisions(snap, channel, version):
    """Finds the revisions for the snap and version in the given channel.

    If you call this function without being logged in with snapcraft, it
    will hang with no output.

    :param str snap: the name of the snap on the snap store
    :param str channel: snap channel to pull revisions from
    :param str version: snap version number, e.g. 1.7.0

    :returns: list of revision numbers
    :rtype: `list` of `str`

    :raises subprocess.CalledProcessError: if the snapcraft command
        fails

    :raises AssertionError: if the expected snaps are not found

    """
    print('Getting revision numbers for', snap, version)
    cmd = ['snapcraft', 'status', snap]
    process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    pattern = f'\\s+{channel}\\s+{version}\\s+(\\d+)\\s*'
    revisions = re.findall(pattern, process.stdout, re.MULTILINE)
    assert len(revisions) == SNAP_ARCH_COUNT, f'Unexpected number of snaps found for {channel} {snap} {version} (expected {SNAP_ARCH_COUNT}, found {len(revisions)})'
    return revisions


def promote_snaps(snaps, source_channel, version, progressive_percentage=None):
    """Promotes the given snaps from source_channel to the stable channel.

    If the snaps have already been released to the stable channel, this
    function will try to release them again which has no effect.

    :param snaps: snap package names to be promoted
    :type snaps: `list` of `str`
    :param str source_channel: snap channel to promote from
    :param str version: the version number that should be found in the
        candidate channel, e.g. 1.7.0
    :param progressive_percentage: specifies the percentage of a progressive
        deployment
    :type progressive_percentage: int or None

    :raises SystemExit: if the command snapcraft is unavailable or it
        isn't logged into an account

    :raises subprocess.CalledProcessError: if a snapcraft command fails
        for another reason

    """
    assert_logged_into_snapcraft()
    for snap in snaps:
        revisions = get_snap_revisions(snap, source_channel, version)
        # The loop below is kind of slow, so let's print some output about what
        # it is doing.
        print('Releasing', snap, 'snaps to the stable channel')
        for revision in revisions:
            cmd = ['snapcraft', 'release', snap, revision, 'stable']
            if progressive_percentage:
                cmd.extend(f'--progressive {progressive_percentage}'.split())
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, universal_newlines=True)
            except subprocess.CalledProcessError as e:
                print("The command", f"'{' '.join(cmd)}'", "failed.")
                print("The output printed to stdout was:")
                print(e.stdout)
                raise

def fetch_version_number():
    """Retrieve latest release version number from GitHub

    :returns: version number

    """
    jq_arg = '.[] | select(.isLatest)|.name'
    cmd = ['gh', 'release', 'list', '--json', 'name,isLatest', '--jq', jq_arg]
    try:
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    except (subprocess.CalledProcessError, OSError):
        print("Getting version number from GitHub release failed.")
        sys.exit(1)

    name = process.stdout.rstrip().split(' ')
    assert len(name) == 2
    version = name[-1]
    assert len(version.split('.')) == 3
    return version


def _sync_candidate_from_temp_to_origin(version: str) -> None:
    cmd = f'git pull temp candidate-{version}'.split()
    subprocess.run(cmd, check=True, universal_newlines=True)
    cmd = f'git push origin candidate-{version}'.split()
    subprocess.run(cmd, check=True, universal_newlines=True)


def _create_release_pr_to_main(version: str) -> None:
    title = f'update files from {version} release'
    body = 'this PR only needs 1 review and should be merged, not squashed'
    cmd = ['gh', 'pr', 'create', '--title', title, '--body', body]
    subprocess.run(cmd, check=True, universal_newlines=True)


def _create_release_pr_to_minor_branch(version: str, point_x_branch_name: str) -> None:
    title = f'update files from {version} release'
    body = 'this PR only needs 1 review and should be merged, not squashed'
    cmd = ['gh', 'pr', 'create', '--title', title, '--body', body, '--base', point_x_branch_name]
    subprocess.run(cmd, check=True, universal_newlines=True)


def _create_and_push_branch_without_version_bump(branch_name: str) -> None:
    cmd = f'git checkout -b {branch_name}'.split()
    subprocess.run(cmd, check=True, universal_newlines=True)
    cmd = 'git reset --hard HEAD~1'.split()
    subprocess.run(cmd, check=True, universal_newlines=True)
    cmd = f'git push origin {branch_name}'.split()
    subprocess.run(cmd, check=True, universal_newlines=True)


def synchonize_github_repo(version: str):
    _sync_candidate_from_temp_to_origin(version)
    _create_release_pr_to_main(version)

    point_version = version.split('.')[-1]
    point_release = point_version != '0'
    point_x_branch_name = '.'.join(version.split('.')[:-1]) + '.x'
    if not point_release:
        branch_name = point_x_branch_name
    else:
        branch_name = f'point-ready-{version}'

    _create_and_push_branch_without_version_bump(branch_name)

    if point_release:
        _create_release_pr_to_minor_branch(version, point_x_branch_name)


def generate_community_forum_post(version: str):
    print('Generating announcement text for community forum post')

    cmd = f"gh release view v{version} --json body -t {{{{.body}}}}".split()

    try:
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    except (subprocess.CalledProcessError, OSError):
        print("Generating announcement text failed.")
        sys.exit(1)

    changelog = process.stdout

    print('Subject:')
    print()
    print(f'Certbot {version} Release')
    print()
    print('Contents:')
    print()
    print(f'Certbot {version} has just been released. The changelog for the release is:')
    print()
    print(changelog)

def main(args):
    parsed_args = parse_args(args)
    version = fetch_version_number()
    version = '1.20.0'
    # promote_snaps(ALL_SNAPS, 'beta', version)
    synchonize_github_repo(version)
    generate_community_forum_post(version)

if __name__ == "__main__":
    main(sys.argv[1:])
