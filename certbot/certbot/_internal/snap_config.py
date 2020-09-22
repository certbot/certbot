"""Module configuring Certbot in a snap environment"""
import socket
import sys

from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool

from acme.magic_typing import List

from certbot.compat import os


_ARCH_TRIPLET_MAP = {
    'arm64': 'aarch64-linux-gnu',
    'armhf': 'arm-linux-gnueabihf',
    'i386': 'i386-linux-gnu',
    'ppc64el': 'powerpc64le-linux-gnu',
    'powerpc': 'powerpc-linux-gnu',
    'amd64': 'x86_64-linux-gnu',
    's390x': 's390x-linux-gnu',
}


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
        sys.stderr.write('Unrecognized value of SNAP_ARCH: {0}\n'.format(snap_arch))
        sys.exit(1)

    os.environ['CERTBOT_AUGEAS_PATH'] = '{0}/usr/lib/{1}/libaugeas.so.0'.format(
        os.environ.get('SNAP'), _ARCH_TRIPLET_MAP[snap_arch])

    session = Session()
    session.mount('http://snapd/', _SnapdAdapter())

    response = session.get('http://snapd/v2/connections?snap=certbot&interface=content')

    if response.status_code == 404:
        sys.stderr.write('An error occurred while fetching Certbot snap plugins: '
                         'your version of snapd is outdated.\n')
        sys.stderr.write('Please run "sudo snap install core" in your terminal and try again.\n')
        sys.exit(1)

    response.raise_for_status()

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
        super(HTTPConnection, self).__init__("localhost")
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("/run/snapd.socket")


class _SnapdConnectionPool(HTTPConnectionPool):
    def __init__(self):
        super(HTTPConnectionPool, self).__init__("localhost")

    def _new_conn(self):
        return _SnapdConnection()


class _SnapdAdapter(HTTPAdapter):
    def get_connection(self, url, proxies=None):
        return _SnapdConnectionPool()
