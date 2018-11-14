#!/usr/bin/env python
# Developer virtualenv setup for Certbot client

from __future__ import absolute_import

import os
import subprocess
import sys

import _venv_common

REQUIREMENTS = [
    '-e acme[dev]',
    '-e .[dev,docs]',
    '-e certbot-apache',
    '-e certbot-dns-cloudflare',
    '-e certbot-dns-cloudxns',
    '-e certbot-dns-digitalocean',
    '-e certbot-dns-dnsimple',
    '-e certbot-dns-dnsmadeeasy',
    '-e certbot-dns-gehirn',
    '-e certbot-dns-google',
    '-e certbot-dns-linode',
    '-e certbot-dns-luadns',
    '-e certbot-dns-nsone',
    '-e certbot-dns-ovh',
    '-e certbot-dns-rfc2136',
    '-e certbot-dns-route53',
    '-e certbot-dns-sakuracloud',
    '-e certbot-nginx',
    '-e certbot-postfix',
    '-e letshelp-certbot',
    '-e certbot-compatibility-test',
]

def get_venv_args():
    with open(os.devnull, 'w') as fnull:
        where_python3_st_code = subprocess.call(
            'where python3', shell=True, stdout=fnull, stderr=fnull)
        command_python3_st_code = subprocess.call(
            'command -v python3', shell=True, stdout=fnull, stderr=fnull)

    if not where_python3_st_code or not command_python3_st_code:
        return '--python python3'

    raise ValueError('Couldn\'t find python3 in {0}'.format(os.environ.get('PATH')))

def main():
    venv_args = get_venv_args()

    _venv_common.main('venv3', venv_args, REQUIREMENTS)

if __name__ == '__main__':
    main()
