#!/usr/bin/env python
"""
Script to notify the person doing the release that the Azure run was successful.

Run:

python tools/notify_mattermost.py MATTERMOST_WEBHOOK_URL
"""
import os
import random
import requests
import sys

repo_name = os.environ['BUILD_REPOSITORY_ID']
build_id = os.environ['BUILD_BUILDID']

def get_greeting():
    fun_greetings = [
        'Hey',
        'Paging',
        'Hi',
        'Pinging',
    ]
    return random.choice(fun_greetings)

def get_message():
    fun_success_messages = [
        'the certbot release is ready to come out of the oven!',
        "it's release-finishing go time!",
        'all certbot release systems are set for launch!',
    ]

    timeline_url = f'https://dev.azure.com/{repo_name}/_apis/build/builds/{build_id}/timeline/?api-version=7.1'
    r = requests.get(timeline_url)
    data = r.json()
    for x in data['records']:
        if x['name'] == 'Changelog':
            deploy_result = x['result']
            break
    print(f'deploy_result is {deploy_result}')

    # or data[-6(-ish)]['result']

    # https://learn.microsoft.com/en-us/rest/api/azure/devops/build/timeline/get?view=azure-devops-rest-7.1
    if deploy_result in ['succeeded', 'succeededWithIssues']:
        message = random.choice(fun_success_messages)
    elif deploy_result in ['skipped', 'failed', 'abandoned']:
        message = "the release pipeline has failed."
    else:
        raise RuntimeError("Unknown stage status result {0}".format(deploy_result))
    return message


def get_mattermost_url():
    # This should be a mattermost webhook url that posts to a specific channel,
    # created by certbotbot, with a file containing the url saved in azure pipelines secret
    # files, under pipelines > library. The secret file will need to be given permission to
    # be used by the specific pipeline, in this case 'release.'
    url_path = sys.argv[1]
    with open(url_path, 'r') as file:
        url = file.read().rstrip()
    return url

def get_headers():
    headers = {
        'Content-Type': 'application/json',
    }
    return headers

def get_content():
    build_url = f'https://dev.azure.com/{repo_name}/_build/results?buildId={build_id}&view=results'

    # We use github author here because it's what we have access to. If the name sometimes
    # changes, add any name it might be. Check the git log.
    requested_for = os.environ.get('BUILD_SOURCEVERSIONAUTHOR', '')
    # This is a map of github username to opensource mattermost username
    usernames_map = {
        'wgreenberg': 'willg',
        'bmw': 'brad',
        'ohemorange': 'erica',
    }

    if requested_for in usernames_map:
        text_body = f'{get_greeting()} @{usernames_map[requested_for]}, {get_message()}\n{build_url}'
    else:
        text_body = (f"{get_greeting()} {requested_for}, {get_message()}\nIf you'd like to get @ mentioned for "
            "releases you do in the future, please modify tools/notify_mattermost.py with your "
            f"git author name.\n{build_url}")

    content = {
        'text': text_body,
    }
    return content

print(get_content())
