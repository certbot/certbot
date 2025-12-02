import os

from setuptools import setup

version = '5.2.0'

install_requires = [
    'google-api-python-client>=1.6.5',
    'google-auth>=2.16.0',
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
