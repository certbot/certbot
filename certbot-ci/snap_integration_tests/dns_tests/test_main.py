#!/usr/bin/env python3
import pytest
import subprocess
import glob
import os
import re


@pytest.fixture(autouse=True, scope="module")
def install_certbot_snap(request):
    with pytest.raises(Exception):
        subprocess.check_call(['certbot', '--version'])
    try:
        snap_folder = request.config.getoption("snap_folder")
        snap_arch = request.config.getoption("snap_arch")
        snap_path = glob.glob(os.path.join(snap_folder, 'certbot_*_{0}.snap'.format(snap_arch)))[0]
        subprocess.check_call(['snap', 'install', '--classic', '--dangerous', snap_path])
        subprocess.check_call(['certbot', '--version'])
        yield
    finally:
        subprocess.call(['snap', 'remove', 'certbot'])


def test_dns_plugin_install(dns_snap_path):
    """
    Test that each DNS plugin Certbot snap can be installed
    and is usable with the Certbot snap.
    """
    plugin_name = re.match(r'^certbot-(dns-\w+)_.*\.snap$',
                           os.path.basename(dns_snap_path)).group(1)
    snap_name = 'certbot-{0}'.format(plugin_name)
    assert plugin_name not in subprocess.check_output(['certbot', 'plugins', '--prepare'],
                                                      universal_newlines=True)

    try:
        subprocess.check_call(['snap', 'install', '--dangerous', dns_snap_path])
        subprocess.check_call(['snap', 'set', 'certbot', 'trust-plugin-with-root=ok'])
        subprocess.check_call(['snap', 'connect', 'certbot:plugin', snap_name])

        assert plugin_name in subprocess.check_output(['certbot', 'plugins', '--prepare'],
                                                      universal_newlines=True)
        subprocess.check_call(['snap', 'connect', snap_name + ':certbot-metadata',
            'certbot:certbot-metadata'])
        subprocess.check_call(['snap', 'install', '--dangerous', dns_snap_path])
    finally:
        subprocess.call(['snap', 'remove', 'plugin_name'])
