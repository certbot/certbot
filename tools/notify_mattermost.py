#!/usr/bin/env python
"""
Script to notify the person doing the release that the Azure run was successful.

Run:

python tools/notify_mattermost.py MATTERMOST_WEBHOOK_URL STATUS

where STATUS is either SUCCESS or FAILURE
"""
import os
import random
import requests
import sys

# We use github author here because it's what we have access to. If the name sometimes
# changes, add any name it might be. Check the git log.
requested_for = os.environ.get('BUILD_SOURCEVERSIONAUTHOR', '')
# This is a map of github username to opensource mattermost username
usernames_map = {
    'wgreenberg': 'willg',
    'bmw': 'brad',
    'ohemorange': 'erica',
}

# This should be a mattermost webhook url that posts to a specific channel,
# created by certbotbot, with a file containing the url saved in azure pipelines secret
# files, under pipelines > library. The secret file will need to be given permission to
# be used by the specific pipeline, in this case 'release.'
url_path = sys.argv[1]
with open(url_path, 'r') as file:
    url = file.read().rstrip()

status = sys.argv[2].rstrip()

headers = {
    'Content-Type': 'application/json',
}

fun_greetings = [
    'Hey',
    'Paging',
    'Hi',
    'Pinging',
]

fun_success_messages = [
    'the certbot release is ready to come out of the oven!',
    "it's release-finishing go time!",
    'all certbot release systems are set for launch!',
]

if status == 'SUCCESS':
    message = random.choice(fun_success_messages)
elif status == 'FAILURE':
    message = "the release pipeline has failed."
else:
    raise RuntimeError("STATUS must be either SUCCESS or FAILURE")

repo_name = os.environ['BUILD_REPOSITORY_ID']
build_id = os.environ['BUILD_BUILDID']
azure_url = f'https://dev.azure.com/{repo_name}/_build/results?buildId={build_id}&view=results'

greeting = random.choice(fun_greetings)

if requested_for in usernames_map:
    text_body = f'{greeting} @{usernames_map[requested_for]}, {message}\n{azure_url}'
else:
    text_body = (f"{greeting} {requested_for}, {message} If you'd like to get @ mentioned for "
        "releases you do in the future, please modify tools/notify_mattermost.py with your "
        f"git author name.\n{azure_url}")

content = {
    'text': text_body,
}

response = requests.request(
    method='POST',
    url=url,
    headers=headers,
    json=content,
)
response.raise_for_status()
