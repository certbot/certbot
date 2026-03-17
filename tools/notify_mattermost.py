#!/usr/bin/env python
"""
Script to notify the person doing the release that the Azure run was successful.

Run:

python tools/notify_mattermost.py GITHUB_AUTHOR_NAME MATTERMOST_WEBHOOK_URL
"""
import random
import requests
import sys

# This should be a mattermost webhook url that posts to a specific channel,
# created by certbotbot, with a file containing the url saved in azure pipelines secret
# files, under pipelines > library. The secret file will need to be given permission to
# be used by the specific pipeline, in this case 'release.'
url_path = sys.argv[2]
with open(url_path, 'r') as file:
    url = file.read().rstrip()

# We use github author here because it's what we have access to. If the name sometimes
# changes, add any name it might be. Check the git log.
requested_for = sys.argv[1].rstrip()
usernames_map = {
    'Will Greenberg': 'willg',
    'Erica Portnoy': 'erica',
    'Brad Warren': 'brad',
    'ohemorange': 'erica',
}

headers = {
    'Content-Type': 'application/json',
}

fun_greetings = [
    'Hey',
    'Paging',
    'Hi',
    'Pinging',
]

fun_messages = [
    'the certbot release is ready to come out of the oven',
    "it's release-finishing go time",
    'all certbot release systems are set for launch',
]

greeting = random.choice(fun_greetings)
message = random.choice(fun_messages)

if requested_for in usernames_map:
    text_body = f'{greeting} @{usernames_map[requested_for]}, {message}!'
else:
    text_body = (f"{greeting} {requested_for}, {message}! If you'd like to get @ mentioned for "
        "releases you do in the future, please modify tools/notify_mattermost.py with your "
        "git author name.")

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
