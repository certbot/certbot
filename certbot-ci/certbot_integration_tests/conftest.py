import os
import json


def pytest_configure(config):
    if not os.environ.get('CERTBOT_INTEGRATION'):
        raise ValueError('Error, CERTBOT_INTEGRATION environment variable is not set !')
    config.acme_xdist = _get_acme_xdist()


def _get_acme_xdist():
    acme_xdist = os.environ.get('CERTBOT_ACME_XDIST')
    if not acme_xdist:
        raise ValueError('Error, CERTBOT_ACME_XDIST environment variable is not set !')

    return json.loads(acme_xdist)
