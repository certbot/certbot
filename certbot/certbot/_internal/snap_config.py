"""Module configuring Certbot in a snap environment"""
import json
import logging
from typing import List

from acme import mureq

from certbot.compat import os
from certbot.errors import Error

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


def prepare_env(cli_args: List[str]) -> List[str]:
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


    try:
        response = mureq.get('http://snapd/v2/connections?snap=certbot&interface=content', unix_socket='/run/snapd.socket')
    except mureq.HTTPException:
        LOGGER.error('An error occurred while fetching Certbot snap plugins: '
                     'make sure the snapd service is running.')
        raise
    if not response.ok:
        if response.status_code == 404:
            LOGGER.error('An error occurred while fetching Certbot snap plugins: '
                         'your version of snapd is outdated.')
            LOGGER.error('Please run "sudo snap install core; sudo snap refresh core" '
                         'in your terminal and try again.')
        raise IOError("Bad HTTP status code from snapd", response.status_code)


    data = json.loads(response.body)
    connections = ['/snap/{0}/current/lib/python3.8/site-packages/'.format(item['slot']['snap'])
                   for item in data.get('result', {}).get('established', [])
                   if item.get('plug', {}).get('plug') == 'plugin'
                   and item.get('plug-attrs', {}).get('content') == 'certbot-1']

    os.environ['CERTBOT_PLUGIN_PATH'] = ':'.join(connections)

    cli_args.append('--preconfigured-renewal')

    return cli_args
