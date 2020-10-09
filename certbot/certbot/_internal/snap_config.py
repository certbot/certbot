"""Module configuring Certbot in a snap environment"""
import logging
import socket

from requests import Session
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError
from requests.exceptions import RequestException

from acme.magic_typing import List
from certbot.compat import os
from certbot.errors import Error

try:
    from urllib3.connection import HTTPConnection
    from urllib3.connectionpool import HTTPConnectionPool
except ImportError:
    # Stub imports for oldest requirements, that will never be used in snaps.
    HTTPConnection = object
    HTTPConnectionPool = object


_ARCH_TRIPLET_MAP = {
    'arm64': 'aarch64-linux-gnu',
    'armhf': 'arm-linux-gnueabihf',
    'i386': 'i386-linux-gnu',
    'ppc64el': 'powerpc64le-linux-gnu',
    'powerpc': 'powerpc-linux-gnu',
    'amd64': 'x86_64-linux-gnu',
    's390x': 's390x-linux-gnu',
}

LOGGER = logging.getLogger(__name__)


def prepare_env(cli_args):
    # type: (List[str]) -> List[str]
    """
    Prepare runtime environment for a certbot execution in snap.
    :param list cli_args: List of command line arguments
    :return: Update list of command line arguments
    :rtype: list
    """
    snap_arch = os.environ.get('SNAP_ARCH')

    if snap_arch not in _ARCH_TRIPLET_MAP:
        raise Error('Unrecognized value of SNAP_ARCH: {0}'.format(snap_arch))

    os.environ['CERTBOT_AUGEAS_PATH'] = '{0}/usr/lib/{1}/libaugeas.so.0'.format(
        os.environ.get('SNAP'), _ARCH_TRIPLET_MAP[snap_arch])

    session = Session()
    session.mount('http://snapd/', _SnapdAdapter())

    try:
        response = session.get('http://snapd/v2/connections?snap=certbot&interface=content')
        response.raise_for_status()
    except RequestException as e:
        if isinstance(e, HTTPError) and e.response.status_code == 404:
            LOGGER.error('An error occurred while fetching Certbot snap plugins: '
                         'your version of snapd is outdated.')
            LOGGER.error('Please run "sudo snap install core; sudo snap refresh core" '
                         'in your terminal and try again.')
        else:
            LOGGER.error('An error occurred while fetching Certbot snap plugins: '
                         'make sure the snapd service is running.')
        raise e

    data = response.json()
    connections = ['/snap/{0}/current/lib/python3.8/site-packages/'.format(item['slot']['snap'])
                   for item in data.get('result', {}).get('established', [])
                   if item.get('plug', {}).get('plug') == 'plugin'
                   and item.get('plug-attrs', {}).get('content') == 'certbot-1']

    os.environ['CERTBOT_PLUGIN_PATH'] = ':'.join(connections)

    cli_args.append('--preconfigured-renewal')

    return cli_args


class _SnapdConnection(HTTPConnection):
    def __init__(self):
        super(_SnapdConnection, self).__init__("localhost")
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/run/snapd.socket")


class _SnapdConnectionPool(HTTPConnectionPool):
    def __init__(self):
        super(_SnapdConnectionPool, self).__init__("localhost")

    def _new_conn(self):
        return _SnapdConnection()


class _SnapdAdapter(HTTPAdapter):
    def get_connection(self, url, proxies=None):
        return _SnapdConnectionPool()
