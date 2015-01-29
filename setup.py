#!/usr/bin/env python
import os
import re
import codecs

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

# read version number (and other metadata) from package init
init_fn = os.path.join(here, 'letsencrypt', '__init__.py')
with codecs.open(init_fn, encoding='utf8') as meta_file:
    content = meta_file.read()
meta = dict(re.findall(r"""__([a-z]+)__ = "([^"]+)""", content))

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
    'pylint>=1.4.0',  # upstream #248
    'tox',
]

setup(
    name="letsencrypt",
    version=meta['version'],
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
