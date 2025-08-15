import os

from setuptools import setup

version = '5.0.0.dev0'

install_requires = [
    'python-digitalocean>=1.11', # 1.15.0 or newer is recommended for TTL support
]

if os.environ.get('SNAP_BUILD'):
    install_requires.append('packaging')
else:
    install_requires.extend([
        # We specify the minimum acme and certbot version as the current plugin
        # version for simplicity. See
        # https://github.com/certbot/certbot/issues/8761 for more info.
        f'acme>={version}',
        f'certbot>={version}',
    ])

setup(
    version=version,
    install_requires=install_requires,
)
