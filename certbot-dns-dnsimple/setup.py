import os

from setuptools import setup

version = '5.2.0.dev0'

install_requires = [
    # This version of lexicon is required to address the problem described in
    # https://github.com/AnalogJ/lexicon/issues/387.
    'dns-lexicon>=3.14.1',
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
