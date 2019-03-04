#!/usr/bin/env python

import shutil
import subprocess
import tempfile
import os

# This script must be run from certbot root path
CERTBOT_REPO_PATH = os.getcwd()

DISTRIBUTION_LIST = [
    'debian:stretch', 'ubuntu:cosmic', 'centos:7'
]

SCRIPT = """\
#!/bin/sh

cd /tmp/certbot
letsencrypt-auto-source/letsencrypt-auto --os-packages-only -n

python2 letsencrypt-auto-source/pieces/create_venv.py /tmp/venv "27" "1"
/tmp/venv/bin/python letsencrypt-auto-source/pieces/pipstrap.py
/tmp/venv/bin/pip install -e acme -e . -e certbot-nginx -e certbot-apache
/tmp/venv/bin/pip freeze >> /tmp/workspace/results_2

python3 letsencrypt-auto-source/pieces/create_venv.py /tmp/venv "37" "1"
/tmp/venv3/bin/python letsencrypt-auto-source/pieces/pipstrap.py
/tmp/venv3/bin/pip install -e acme -e . -e certbot-nginx -e certbot-apache
/tmp/venv3/bin/pip freeze >> /tmp/workspace/results_3
"""


def process_one_distribution(distribution):
    workspace = tempfile.mkdtemp()
    script = os.path.join(workspace, 'script.sh')
    try:
        with open(script, 'w') as file_handler:
            file_handler.write(SCRIPT)
        with open(script, 'r') as file_handler:
            print(file_handler.read())
        os.chmod(script, 0o755)
        command = ['docker', 'run', '--rm', '-v', '{0}:/tmp/certbot'.format(CERTBOT_REPO_PATH),
                   '-v', '{0}:/tmp/workspace'.format(workspace), distribution, '/tmp/workspace/script.sh']
        subprocess.check_call(command)
        with open(os.path.join(workspace, 'results_2'), 'r') as file_handler_2:
            with open(os.path.join(workspace, 'results_3', 'r')) as file_handler_3:
                return file_handler_2.read(), file_handler_3.read()
    finally:
        shutil.rmtree(workspace)


def main():
    for distribution in DISTRIBUTION_LIST:
        results = process_one_distribution(distribution)
        print(results)


if __name__ == '__main__':
    main()
