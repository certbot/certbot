#!/usr/bin/env python
"""
Script to generate a message notifying the person doing the release
of the result of the workflow run.

Run:

python tools/release_message.py GITHUB_AUTHOR_NAME SUCCESS

where SUCCESS is True or False
"""
import os
import random
import sys

server_url = os.environ['GITHUB_SERVER_URL']
repo_name = os.environ['GITHUB_REPOSITORY']
run_id = os.environ['GITHUB_RUN_ID']

def get_greeting():
    fun_greetings = [
        'Hey',
        'Paging',
        'Hi',
        'Pinging',
    ]
    return random.choice(fun_greetings)

def get_message(success: bool):
    fun_success_messages = [
        'the certbot release is ready to come out of the oven!',
        "it's release-finishing go time!",
        'all certbot release systems are set for launch!',
    ]

    if success:
        message = random.choice(fun_success_messages)
    else:
        message = "the release pipeline has failed."
    return message

def get_content(requested_for: str, success: bool):
    build_url = f'{server_url}/{repo_name}/actions/runs/{run_id}'

    # We use github author here because it's what we have access to. If the name sometimes
    # changes, add any name it might be. Check the git log.
    # This is a map of team member github author names to opensource mattermost username
    usernames_map = {
        'Will Greenberg': 'willg',
        'Erica Portnoy': 'erica',
        'Brad Warren': 'brad',
        'ohemorange': 'erica',
    }

    if requested_for in usernames_map:
        text_body = f'{get_greeting()} @{usernames_map[requested_for]}, {get_message(success)}\n{build_url}'
    else:
        text_body = (f"{get_greeting()} {requested_for}, {get_message(success)}\nIf you'd like to get @ mentioned for "
            "releases you do in the future, please modify tools/release_message.py with your "
            f"git author name.\n{build_url}")
    return text_body

random.seed()
requested_for: str = sys.argv[1].rstrip()
success: bool = (sys.argv[2].rstrip().lower() == 'true')
print(get_content(requested_for, success))
