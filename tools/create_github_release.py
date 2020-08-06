#!/usr/bin/env python
"""
Post-release script to download artifacts from azure pipelines and use them to create
a GitHub release.

Setup:
 - Create a github personal access token
   - https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token#creating-a-token
   - You'll need repo scope
   - Save the token to somewhere like ~/.ssh/githubpat.txt

Run:

python tools/create_github_release.py ~/.ssh/githubpat.txt
"""

import requests
import sys
import tempfile
from zipfile import ZipFile

from azure.devops.connection import Connection
from github import Github

def download_azure_artifacts(tempdir):
    """Download and unzip build artifacts from Azure pipelines.

    :param str path: path to a temporary directory to save the files

    :returns: released certbot version number as a prefix-free string
    :rtype: str

    """
    # Create a connection to the azure org
    organization_url = 'https://dev.azure.com/certbot'
    connection = Connection(base_url=organization_url)

    # Find the build artifacts
    build_client = connection.clients.get_build_client()
    get_builds_response = build_client.get_builds('certbot', definitions='3')
    build_id = get_builds_response.value[0].id
    artifacts = build_client.get_artifacts('certbot', build_id)

    # Save and unzip files
    for filename in ('windows-installer', 'changelog'):
        url = build_client.get_artifact('certbot', build_id, filename).resource.download_url
        r = requests.get(url)
        r.raise_for_status()
        with open(tempdir + '/' + filename + '.zip', 'wb') as f:
            f.write(r.content)
        with ZipFile(tempdir + '/' + filename + '.zip', 'r') as zipObj:
           zipObj.extractall(tempdir)

    version = build_client.get_build('certbot', build_id).source_branch.split('v')[1]
    return version

def create_github_release(github_access_token, tempdir, version):
    """Use build artifacts to create a github release, including uploading additional assets

    :param str github_access_token: string containing github access token
    :param str path: path to a temporary directory where azure artifacts are located
    :param str version: Certbot version number, e.g. 1.7.0

    """
    # Create release
    g = Github(github_access_token)
    repo = g.get_user('certbot').get_repo('certbot')
    release_notes = open(tempdir + '/changelog/release_notes.md', 'r').read()
    release= repo.create_git_release('v{0}'.format(version),
                                     'Certbot {0}'.format(version),
                                     release_notes,
                                     draft=True)

    # Upload windows installer to release
    release.upload_asset(tempdir + '/windows-installer/certbot-beta-installer-win32.exe')
    release.update_release(release.title, release.body, draft=False)

def main(args):
    github_access_token_file = args[0]

    github_access_token = open(github_access_token_file, 'r').read().rstrip()

    with tempfile.TemporaryDirectory() as tempdir:
        version = download_azure_artifacts(tempdir)
        create_github_release(github_access_token, tempdir, version)

if __name__ == "__main__":
    main(sys.argv[1:])
