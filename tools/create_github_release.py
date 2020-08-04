import requests
import sys
import tempfile
import urllib.parse
from zipfile import ZipFile

from azure.devops.connection import Connection
from github import Github
from msrest.authentication import BasicAuthentication

# Create an azure personal access token
# https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate
# you'll need read scope (I just made a token with all the reads)

# Create a github personal access token
# https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token#creating-a-token
# you'll need repo scope

def download_azure_artifacts(azure_access_token, tempdir):
    # Create a connection to the azure org
    organization_url = 'https://dev.azure.com/certbot'
    credentials = BasicAuthentication('', azure_access_token)
    connection = Connection(base_url=organization_url, creds=credentials)

    # Find the build artifacts
    build_client = connection.clients.get_build_client()
    get_builds_response = build_client.get_builds('certbot', definitions='3')
    build_id = get_builds_response.value[0].id
    artifacts = build_client.get_artifacts('certbot', build_id)

    # Save and unzip files
    for filename in ('windows-installer', 'changelog'):
        url = build_client.get_artifact('certbot', build_id, filename).resource.download_url
        r = requests.get(url)
        with open(tempdir + '/' + filename + '.zip', 'wb') as f:
            f.write(r.content)
        with ZipFile(tempdir + '/' + filename + '.zip', 'r') as zipObj:
           zipObj.extractall(tempdir)

def create_github_release(github_access_token, tempdir, version):
    # Create release
    g = Github(github_access_token)
    repo = g.get_user('certbot').get_repo('certbot')
    release_notes = open(tempdir + '/changelog/release_notes.md', 'r').read()
    release= repo.create_git_release('v{0}'.format(version),
                                     'Certbot {0}'.format(version),
                                     release_notes)

    # Upload windows installer to release
    release.upload_asset(tempdir + '/windows-installer/certbot-beta-installer-win32.exe')

def main(args):
    version = args[0]
    azure_access_token_file = args[1]
    github_access_token_file = args[2]

    azure_access_token = open(azure_access_token_file, 'r').read()
    github_access_token = open(github_access_token_file, 'r').read()

    with tempfile.TemporaryDirectory() as tempdir:
        download_azure_artifacts(azure_access_token, tempdir)
        create_github_release(github_access_token, tempdir, version)

if __name__ == "__main__":
    main(sys.argv[1:])