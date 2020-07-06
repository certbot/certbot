#!/usr/bin/env python3
import pytest
import subprocess
import glob
import os
import re


def _get_snap_directory():
    snap_directory = os.environ.get('SNAP_FOLDER')
    if not snap_directory:
        raise ValueError('Error, SNAP_FOLDER environment variable is not set.')

    return snap_directory


def _list_dns_snaps_paths():
    snap_directory = _get_snap_directory()
    if not snap_directory:
        raise ValueError('Error, SNAP_FOLDER environment variable is not set.')

    return glob.glob(os.path.join(snap_directory, 'certbot-dns-*_*.snap'))


def _extract_plugin_name(dns_snap_path):
    return re.match(r'^.*certbot-(dns-\w+)_.*\.snap$', dns_snap_path).group(1)


@pytest.fixture(autouse=True, scope="module")
def install_certbot_snap():
    with pytest.raises(Exception):
        subprocess.check_call(['certbot', '--version'])
    try:
        snap_directory = _get_snap_directory()
        snap_path = glob.glob(os.path.join(snap_directory, 'certbot_*.snap'))[0]
        subprocess.check_call(['snap', 'install', '--classic', '--dangerous', snap_path])
        subprocess.check_call(['certbot', '--version'])
        yield
    finally:
        subprocess.call(['snap', 'remove', 'certbot'])


@pytest.mark.parametrize('dns_snap_path', _list_dns_snaps_paths())
def test_it(dns_snap_path):
    """
    Test that each DNS plugin Certbot snap available in SNAP_FOLDER
    can be installed and is usable with the Certbot snap.
    """
    plugin_name = _extract_plugin_name(dns_snap_path)
    snap_name = 'certbot-{0}'.format(plugin_name)
    assert plugin_name not in subprocess.check_output(['certbot', 'plugins', '--prepare'],
                                                      universal_newlines=True)

    try:
        subprocess.check_call(['snap', 'install', '--dangerous', dns_snap_path])
        subprocess.check_call(['snap', 'set', 'certbot', 'trust-plugin-with-root=ok'])
        subprocess.check_call(['snap', 'connect', 'certbot:plugin', snap_name])

        assert plugin_name in subprocess.check_output(['certbot', 'plugins', '--prepare'],
                                                      universal_newlines=True)
    finally:
        subprocess.call(['snap', 'remove', 'plugin_name'])
