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
SKIP_SYNC_MESSAGE = ('To skip pushing updated branches to GitHub and creating PRs, '
                     'run this script with the `--skip-github-sync` flag.')


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
    parser.add_argument('--test-version', type=str, default=None,
                        help='version in the form of 1.2.3, mainly for testing')
    parser.add_argument('--skip-snaps', action='store_true',
                        help='don\'t promote snaps; used for testing')
    parser.add_argument('--skip-github-sync', action='store_true',
                        help='don\'t synchronize branches to GitHub or create PRs')
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


def _run_silent_except_error(cmd: list[str], message: str = None) -> subprocess.CompletedProcess:
    # For some reason, git prints a bunch of non-error output to stderr. Let's keep this script
    # quiet by capturing it and only printing it if we hit an error.
    try:
        process = subprocess.run(cmd, check=True, universal_newlines=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f'Error running `{' '.join(cmd)}`')
        if message is not None:
            print(message)
        print(e.output)
        print(e.stderr)
        print(SKIP_SYNC_MESSAGE)
        raise e
    else:
        return process


def _create_pr(title: str, body: str, description: str, other_opts: list[str] | None = None) -> str:
    cmd = ['gh', 'pr', 'create', '--title', title, '--body', body]
    if other_opts is not None:
        cmd = cmd + other_opts
    try:
        proc = subprocess.run(cmd, check=True, universal_newlines=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        if 'already exists' in e.stderr:
            print(f'{description} already exists...skipping creation. '
                   'To create a new PR, delete the old one on GitHub.')
            # The error message looks like:
            # a pull request for branch "candidate-4.24.0" into branch "main" already exists:
            # https://github.com/certbot/certbot/pull/10698
            last_e_word = e.stderr.split()[-1]
            if 'https' in last_e_word:
                output = last_e_word
        else:
            print(e.stderr)
            print(SKIP_SYNC_MESSAGE)
            raise e
    else:
        output = proc.stdout.rstrip()
    return output


def _sync_candidate_from_temp_to_origin(version: str) -> None:
    command_str = f'git pull temp candidate-{version}'
    message = ('To run successfully, stash any changes you\'ve made to this branch. '
               'Do not attempt to merge and continue, as that will fail.')
    _run_silent_except_error(command_str.split(), message)
    command_str = f'git push origin candidate-{version}'
    message = ('To delete the branch on GitHub, run '
              f'`git push origin --delete candidate-{version}`.')
    _run_silent_except_error(command_str.split(), message)


def _create_release_pr_to_main(version: str) -> None:
    print(f'Creating PR to merge candidate-{version} into main...')
    title = f'update files from {version} release'
    body = 'this PR only needs 1 review and should be merged, not squashed'
    result = _create_pr(title, body, 'PR to merge release changes into main')
    print(f'PR location: {result}')


def _create_release_pr_to_minor_branch(
        version: str,
        branch_name:str,
        point_x_branch_name: str) -> None:
    print(f'Creating PR to merge {branch_name} into {point_x_branch_name}...')
    title = f'update files from {version} release'
    body = 'this PR only needs 1 review and should be merged, not squashed'
    pr_opts = [ '--head', branch_name,
                '--base', point_x_branch_name]
    result = _create_pr(title, body, 'PR to merge release changes into .x branch', create_pr_opts)
    print(f'PR location: {result}')


def _create_and_push_branch_without_version_bump(version: str, branch_name: str) -> None:
    # Usually a branch of form 1.2.x
    # When it's a point release, it'll be any name, and then merged back into 1.2.x
    print(f'Creating branch without version bump commit named {branch_name}...')
    # Check if there are uncommited changes, since reset will blow them away

    message = ('You have uncommitted changes that will be deleted. '
               'Stash your changes before rerunning this script.')
    _run_silent_except_error('git diff --quiet HEAD'.split(), message)
    try:
        msg = (f'Branch {branch_name} already exists. Delete it using '
               f'`git branch -D {branch_name}`.')
        _run_silent_except_error(f'git branch {branch_name}'.split(), msg)

        _run_silent_except_error(f'git switch {branch_name}'.split())

        # Make sure the last commit message is 'Bump version to {next version}'
        output = _run_silent_except_error('git log -1 --pretty=%B'.split()).stdout
        assert_msg = 'The most recent commit message should start with "Bump version to"'
        assert output.startswith('Bump version to'), assert_msg

        _run_silent_except_error('git reset --hard HEAD~1'.split())

        msg = ('You shouldn\'t be trying to re-push a minor version branch. If you really want '
               'to, go into GitHub, turn off branch deletion protection, and delete it there. ')
        _run_silent_except_error(f'git push origin {branch_name}'.split(), msg)
    finally:
        # Switching to the current branch exits 0
        _run_silent_except_error(f'git switch candidate-{version}'.split())
    print('Created.')


def _check_branch_matches_version(version: str) -> None:
    # This function assumes we're on a branch like `candidate-1.2.0` or `candidate-1.2.3`
    # where the number after candidate should be equal to the version number
    process = _run_silent_except_error('git branch --show'.split())
    current_branch = process.stdout.rstrip()
    if current_branch != f'candidate-{version}':
        print(f'Unexpected branch name found. The current branch should be candidate-{version}.')
        print(SKIP_SYNC_MESSAGE)
        sys.exit(1)


def synchronize_github_repo(version: str):
    _check_branch_matches_version(version)

    _sync_candidate_from_temp_to_origin(version)
    _create_release_pr_to_main(version)

    # Check the last element of the version number to see if this is a point release
    point_version = version.split('.')[-1]
    point_release = point_version != '0'
    point_x_branch_name = '.'.join(version.split('.')[:-1]) + '.x'
    if not point_release:
        branch_name = point_x_branch_name
    else:
        branch_name = f'point-candidate-{version}'

    _create_and_push_branch_without_version_bump(version, branch_name)

    if point_release:
        _create_release_pr_to_minor_branch(version, branch_name, point_x_branch_name)


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
    version = parsed_args.test_version
    if not version:
        version = fetch_version_number()
    if not parsed_args.skip_snaps:
        promote_snaps(ALL_SNAPS, 'beta', version)
    if not parsed_args.skip_github_sync:
        synchronize_github_repo(version)
    generate_community_forum_post(version)

if __name__ == "__main__":
    main(sys.argv[1:])
