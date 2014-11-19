#!/usr/bin/env python
from setuptools import setup
setup(
    name="trustify",
    version="0.1",
    description="Trustify",
    author="Trustify project",
    license="",
    url="https://letsencrypt.org",
    packages=[
        'letsencrypt',
        'letsencrypt.client',
    ],
    install_requires=[
        #'dialog',
        'requests',
        'jose',
        'jsonschema',
        'M2Crypto',
        'pycrypto',
        #'python-augeas',
        'python2-pythondialog',
    ],
    entry_points={
        'console_scripts': [
            'trustify = trustify.client.client:authenticate'
        ]
    },
)
