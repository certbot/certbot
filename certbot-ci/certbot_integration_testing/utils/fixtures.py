import os
import subprocess

import pytest


@pytest.fixture(scope='session')
def acme_url():
    integration = os.environ.get('CERTBOT_INTEGRATION')

    if integration == 'boulder-v1':
        return 'http://localhost:4000/directory'
    if integration == 'boulder-v2':
        return 'http://localhost:4001/directory'
    if integration == 'pebble' or integration == 'pebble-strict':
        return 'https://localhost:14000/dir'

    raise ValueError('Invalid CERTBOT_INTEGRATION value')


@pytest.fixture(scope='session')
def exec_certbot_base(acme_url):
    omit_patterns = (
        '*/*.egg-info/*,*/dns_common*,*/setup.py,*/test_*,*/tests/*',
        '$omit_patterns,*_test.py,*_test_*,certbot-apache/*',
        '$omit_patterns,certbot-compatibility-test/*,certbot-dns*/',
        '$omit_patterns,certbot-nginx/certbot_nginx/parser_obj.py'
    )
    def func(*args):
        command = [
            'coverage', 'run', '--append', '--source', sources, '--omit', omit_patterns
        ]

        command.extend(args)

        subprocess.check_call(command)

    return func()
