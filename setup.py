#!/usr/bin/env python
from setuptools import setup


setup(
    name="letsencrypt",
    version="0.1",
    description="Let's Encrypt",
    author="Let's Encrypt Project",
    license="",
    url="https://letsencrypt.org",
    packages=[
        'letsencrypt',
        'letsencrypt.client',
        'letsencrypt.scripts',
    ],
    install_requires=[
        #'dialog',
        'requests',
        'jsonschema',
        'M2Crypto',
        'pycrypto',
        #'python-augeas',
        'python2-pythondialog',
    ],
    entry_points={
        'console_scripts': [
            'letsencrypt = letsencrypt.scripts.main:main'
        ]
    },
    zip_safe=False,
    include_package_data=True,
)
