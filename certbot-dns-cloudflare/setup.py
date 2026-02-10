import os

from setuptools import setup

version = '5.3.1'

install_requires = [
    # for now, do not upgrade to cloudflare>=2.20 to avoid deprecation warnings and the breaking
    # changes in version 3.0. see https://github.com/certbot/certbot/issues/9938
    'cloudflare>=2.19, <2.20',
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
