#!/usr/bin/env python
from setuptools import setup


install_requires = [
    'argparse',
    'jsonschema',
    'mock',
    'pycrypto',
    'python-augeas',
    'python2-pythondialog',
    'requests',
    'zope.component',
    'zope.interface',
    # order of items in install_requires DOES matter and M2Crypto has
    # to go last, see #152
    'M2Crypto',
]

docs_extras = [
    'Sphinx',
]

testing_extras = [
    'coverage',
    'nose',
    'nosexcover',
    'pylint<1.4',  # py2.6 compat, c.f #97
    'astroid<1.3.0',  # py2.6 compat, c.f. #187
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
        'letsencrypt.client.apache',
        'letsencrypt.client.tests',
        'letsencrypt.client.tests.apache',
        'letsencrypt.scripts',
    ],
    install_requires=install_requires,
    tests_require=install_requires,
    test_suite='letsencrypt',
    extras_require={
        'docs': docs_extras,
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
