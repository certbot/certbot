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
        command_python2_st_code = subprocess.call(
            'command -v python2', shell=True, stdout=fnull, stderr=fnull)
        if not command_python2_st_code:
            return '--python python2'

        command_python27_st_code = subprocess.call(
            'command -v python2.7', shell=True, stdout=fnull, stderr=fnull)
        if not command_python27_st_code:
            return '--python python2.7'

    raise ValueError('Couldn\'t find python2 or python2.7 in {0}'.format(os.environ.get('PATH')))

def main():
    if os.name == 'nt':
        raise ValueError('Certbot for Windows is not supported on Python 2.x.')

    venv_args = get_venv_args()

    _venv_common.main('venv', venv_args, REQUIREMENTS)

if __name__ == '__main__':
    main()
