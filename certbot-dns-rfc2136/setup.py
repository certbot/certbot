import os

from setuptools import setup

version = '5.1.0'

install_requires = [
    # This version was chosen because it is the version packaged in RHEL 9 and Debian unstable. It
    # is possible this requirement could be relaxed to allow for an even older version of dnspython
    # if necessary.
    'dnspython>=2.6.1',
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

