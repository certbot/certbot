#!/usr/bin/env python
from setuptools import setup


install_requires = [
    'argparse',
    'jsonschema',
    'M2Crypto',
    'pycrypto',
    'python-augeas',
    'python2-pythondialog',
    'requests',
]

testing_extras = [
    'coverage',
    'nose',
    'pylint',
    'tox',
]

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
    install_requires=install_requires,
    tests_require=install_requires,
    test_suite='letsencrypt',
    extras_require={
        'testing': testing_extras,
    },
    entry_points={
        'console_scripts': [
            'letsencrypt = letsencrypt.scripts.main:main',
        ],
    },
    zip_safe=False,
    include_package_data=True,
)
