# pylint: disable=missing-module-docstring
import atexit
import importlib.resources
import io
import json
import os
import platform
import stat
import zipfile
from contextlib import ExitStack
from typing import Optional, Tuple

import requests

from certbot_integration_tests.utils.constants import DEFAULT_HTTP_01_PORT
from certbot_integration_tests.utils.constants import MOCK_OCSP_SERVER_PORT

PEBBLE_VERSION = 'v2.7.0'


def fetch(workspace: str, http_01_port: int = DEFAULT_HTTP_01_PORT) -> Tuple[str, str, str]:
    # pylint: disable=missing-function-docstring
    file_manager = ExitStack()
    atexit.register(file_manager.close)
    pebble_path_ref = importlib.resources.files('certbot_integration_tests') / 'assets'
    assets_path = str(file_manager.enter_context(importlib.resources.as_file(pebble_path_ref)))

    pebble_path = _fetch_asset('pebble', assets_path)
    challtestsrv_path = _fetch_asset('pebble-challtestsrv', assets_path)
    pebble_config_path = _build_pebble_config(workspace, http_01_port, assets_path)

    return pebble_path, challtestsrv_path, pebble_config_path


def _fetch_asset(asset: str, assets_path: str) -> str:
    base_url = 'https://github.com/letsencrypt/pebble/releases/download'
    os_type, architecture = _get_validated_os_and_architecture()
    asset_path = os.path.join(assets_path, f'{asset}_{PEBBLE_VERSION}_{os_type}_{architecture}')
    if not os.path.exists(asset_path):
        asset_url = f'{base_url}/{PEBBLE_VERSION}/{asset}-{os_type}-{architecture}.zip'
        response = requests.get(asset_url, timeout=30)
        response.raise_for_status()
        asset_data = _unzip_asset(response.content, asset)
        if asset_data is None:
            raise ValueError(f"zipfile {asset_url} didn't contain file {asset}")
        with open(asset_path, 'wb') as file_h:
            file_h.write(asset_data)
    os.chmod(asset_path, os.stat(asset_path).st_mode | stat.S_IEXEC)

    return asset_path


def _get_validated_os_and_architecture() -> tuple[str, str]:
    os_type = platform.system().lower()
    if os_type not in ('darwin', 'linux'):
        raise ValueError(f'this code has not been tested on {os_type} systems')

    architecture = platform.machine()
    if architecture in ('amd64', 'x86_64'):
        architecture = 'amd64'
    elif architecture in ('aarch64' 'arm64'):
        architecture = 'arm64'
    else:
        raise ValueError(f'this code has not been tested on {architecture} systems')

    return os_type, architecture


def _unzip_asset(zipped_data: bytes, asset_name: str) -> Optional[bytes]:
    with zipfile.ZipFile(io.BytesIO(zipped_data)) as zip_file:
        for entry in zip_file.filelist:
            if not entry.is_dir() and entry.filename.endswith(asset_name):
                return zip_file.read(entry)
    return None


def _build_pebble_config(workspace: str, http_01_port: int, assets_path: str) -> str:
    config_path = os.path.join(workspace, 'pebble-config.json')
    with open(config_path, 'w') as file_h:
        file_h.write(json.dumps({
            'pebble': {
                'listenAddress': '0.0.0.0:14000',
                'managementListenAddress': '0.0.0.0:15000',
                'certificate': os.path.join(assets_path, 'cert.pem'),
                'privateKey': os.path.join(assets_path, 'key.pem'),
                'httpPort': http_01_port,
                'tlsPort': 5001,
                'ocspResponderURL': 'http://127.0.0.1:{0}'.format(MOCK_OCSP_SERVER_PORT),
            },
        }))

    return config_path
