# pylint: disable=missing-module-docstring

import json
import os
import stat
from typing import Tuple

import pkg_resources
import requests

from certbot_integration_tests.utils.constants import DEFAULT_HTTP_01_PORT
from certbot_integration_tests.utils.constants import MOCK_OCSP_SERVER_PORT

PEBBLE_VERSION = 'v2.3.0'
ASSETS_PATH = pkg_resources.resource_filename('certbot_integration_tests', 'assets')


def fetch(workspace: str, http_01_port: int = DEFAULT_HTTP_01_PORT) -> Tuple[str, str, str]:
    # pylint: disable=missing-function-docstring
    suffix = 'linux-amd64' if os.name != 'nt' else 'windows-amd64.exe'

    pebble_path = _fetch_asset('pebble', suffix)
    challtestsrv_path = _fetch_asset('pebble-challtestsrv', suffix)
    pebble_config_path = _build_pebble_config(workspace, http_01_port)

    return pebble_path, challtestsrv_path, pebble_config_path


def _fetch_asset(asset: str, suffix: str) -> str:
    asset_path = os.path.join(ASSETS_PATH, '{0}_{1}_{2}'.format(asset, PEBBLE_VERSION, suffix))
    if not os.path.exists(asset_path):
        asset_url = ('https://github.com/letsencrypt/pebble/releases/download/{0}/{1}_{2}'
                     .format(PEBBLE_VERSION, asset, suffix))
        response = requests.get(asset_url)
        response.raise_for_status()
        with open(asset_path, 'wb') as file_h:
            file_h.write(response.content)
    os.chmod(asset_path, os.stat(asset_path).st_mode | stat.S_IEXEC)

    return asset_path


def _build_pebble_config(workspace: str, http_01_port: int) -> str:
    config_path = os.path.join(workspace, 'pebble-config.json')
    with open(config_path, 'w') as file_h:
        file_h.write(json.dumps({
            'pebble': {
                'listenAddress': '0.0.0.0:14000',
                'managementListenAddress': '0.0.0.0:15000',
                'certificate': os.path.join(ASSETS_PATH, 'cert.pem'),
                'privateKey': os.path.join(ASSETS_PATH, 'key.pem'),
                'httpPort': http_01_port,
                'tlsPort': 5001,
                'ocspResponderURL': 'http://127.0.0.1:{0}'.format(MOCK_OCSP_SERVER_PORT),
            },
        }))

    return config_path
