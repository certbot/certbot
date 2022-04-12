#!/usr/bin/env python
"""
Post-release script to publish artifacts created from Azure Pipelines.

This currently includes:

* Moving snaps from the beta channel to the stable channel
* Publishing the Windows installer in a GitHub release

Setup:
 - Install the snapcraft command line tool and log in to a privileged account.
   - https://snapcraft.io/docs/installing-snapcraft
   - Use the command `snapcraft login` to log in.

Run:

python tools/finish_release.py --css <URL of code signing server>

Testing:

This script can be safely run between releases. When this is done, the script
should execute successfully until the final step when it tries to set draft
equal to false on the GitHub release. This step should fail because a published
release with that name already exists.

"""

import argparse
import glob
import os.path
import re
import subprocess
import sys
import tempfile
import getpass
from azure.devops.connection import Connection
from zipfile import ZipFile

import requests

# Path to the root directory of the Certbot repository containing this script
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# This list contains the names of all Certbot DNS plugins
DNS_PLUGINS = [os.path.basename(path) for path in glob.glob(os.path.join(REPO_ROOT, 'certbot-dns-*'))]
# This list contains the name of all Certbot snaps that should be published to
# the stable channel.
SNAPS = ['certbot'] + DNS_PLUGINS
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
    parser.add_argument('--css', type=str, required=True, help='hostname of code signing server')
    group = parser.add_mutually_exclusive_group()
    # We use 'store_false' and a destination related to the other type of
    # artifact to cause the flag being set to disable publishing of the other
    # artifact. This makes using the parsed arguments later on a little simpler
    # and cleaner.
    group.add_argument('--snaps-only', action='store_false', dest='publish_windows',
                        help='Skip publishing other artifacts and only publish the snaps')
    group.add_argument('--windows-only', action='store_false', dest='publish_snaps',
                        help='Skip publishing other artifacts and only publish the Windows installer')
    return parser.parse_args(args)

    
def publish_windows(css):
    """SSH into CSS and trigger downloading Azure Pipeline assets, sign, and upload to Github

    :param str css: CSS host name

    """
    username = getpass.getuser()
    host = css
    command = ["ssh", username + "@" + host, "./certbot-misc/css/venv.sh"]
    
    print("SSH into CSS to trigger signing and uploading of Windows installer...")
    subprocess.run(command, check=True, universal_newlines=True)


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
        print("'snapcraft login'.")
        sys.exit(1)


def get_snap_revisions(snap, version):
    """Finds the revisions for the snap and version in the beta channel.

    If you call this function without being logged in with snapcraft, it
    will hang with no output.

    :param str snap: the name of the snap on the snap store
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
    pattern = f'^\s+beta\s+{version}\s+(\d+)\s*$'
    revisions = re.findall(pattern, process.stdout, re.MULTILINE)
    assert len(revisions) == SNAP_ARCH_COUNT, f'Unexpected number of snaps found for {snap} {version}'
    return revisions


def promote_snaps(version):
    """Promotes all Certbot snaps from the beta to stable channel.

    If the snaps have already been released to the stable channel, this
    function will try to release them again which has no effect.

    :param str version: the version number that should be found in the
        beta channel, e.g. 1.7.0

    :raises SystemExit: if the command snapcraft is unavailable or it
        isn't logged into an account

    :raises subprocess.CalledProcessError: if a snapcraft command fails
        for another reason

    """
    assert_logged_into_snapcraft()
    for snap in SNAPS:
        revisions = get_snap_revisions(snap, version)
        # The loop below is kind of slow, so let's print some output about what
        # it is doing.
        print('Releasing', snap, 'snaps to the stable channel')
        for revision in revisions:
            cmd = ['snapcraft', 'release', snap, revision, 'stable']
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, universal_newlines=True)
            except subprocess.CalledProcessError as e:
                print("The command", f"'{' '.join(cmd)}'", "failed.")
                print("The output printed to stdout was:")
                print(e.stdout)
                raise

def fetch_version_number():
    """Retrieve version number for release from Azure Pipelines

    :returns: version number
    
    """
    # Create a connection to the azure org
    organization_url = 'https://dev.azure.com/certbot'
    connection = Connection(base_url=organization_url)
    
    # Find the build artifacts
    build_client = connection.clients.get_build_client()
    get_builds_response = build_client.get_builds('certbot', definitions='3')
    build_id = get_builds_response.value[0].id
    version = build_client.get_build('certbot', build_id).source_branch.split('v')[1]
    return version

def main(args):
    parsed_args = parse_args(args)

    css = parsed_args.css
    version = fetch_version_number()

    # Once the GitHub release has been published, trying to publish it
    # again fails. Publishing the snaps can be done multiple times though
    # so we do that first to make it easier to run the script again later
    # if something goes wrong.        
    if parsed_args.publish_snaps:
        promote_snaps(version)
    if parsed_args.publish_windows:
        publish_windows(css)

if __name__ == "__main__":
    main(sys.argv[1:])
