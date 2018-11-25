import os
import pytest


@pytest.fixture(scope='session')
def acme_url():
    integration = os.environ.get('CERTBOT_INTEGRATION')

    if integration == 'boulder-v1':
        return 'http://localhost:4000/directory'
    if integration == 'boulder-v2':
        return 'http://localhost:4001/directory'
    if integration == 'pebble-nonstrict' or integration == 'pebble-strict':
        return 'https://localhost:14000/dir'

    raise ValueError('Invalid CERTBOT_INTEGRATION value: {0}'.format(integration))


@pytest.fixture(scope='session')
def tls_sni_01_port():
    return 5001


@pytest.fixture(scope='session')
def http_01_port():
    return 5002

