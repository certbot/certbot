#!/usr/bin/env python
from setuptools import setup


setup(
    name="letsencrypt",
    version="0.1",
    description="Let's Encrypt",
    author="Let's Encrypt project",
    license="",
    url="https://letsencrypt.org",
    packages=[
        'letsencrypt',
        'letsencrypt.client',
    ],
    install_requires=[
        'jose',
        'jsonschema',
        'M2Crypto',
        'pycrypto',
        #'python-augeas',
        'python2-pythondialog',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'letsencrypt = letsencrypt.client.client:authenticate'
        ]
    },
)
