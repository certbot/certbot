#!/usr/bin/env python
import codecs
import os
import re

from setuptools import setup


def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()


here = os.path.abspath(os.path.dirname(__file__))

# read version number (and other metadata) from package init
init_fn = os.path.join(here, 'letsencrypt', '__init__.py')
meta = dict(re.findall(r"""__([a-z]+)__ = "([^"]+)""", read_file(init_fn)))

readme = read_file(os.path.join(here, 'README.rst'))
changes = read_file(os.path.join(here, 'CHANGES.rst'))

install_requires = [
    'argparse',
    'ConfArgParse',
    'jsonschema',
    'mock',
    'psutil>=2.1.0',  # net_connections introduced in 2.1.0
    'pycrypto',
    'PyOpenSSL',
    'python-augeas',
    'python2-pythondialog',
    'requests',
    'zope.component',
    'zope.interface',
    # order of items in install_requires DOES matter and M2Crypto has
    # to go last, see #152
    'M2Crypto',
]

dev_extras = [
    'pylint>=1.4.0',  # upstream #248
]

docs_extras = [
    'repoze.sphinx.autointerface',
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

testing_extras = [
    'coverage',
    'nose',
    'nosexcover',
    'tox',
]

setup(
    name="letsencrypt",
    version=meta['version'],
    description="Let's Encrypt",
    long_description=readme,  # later: + '\n\n' + changes
    author="Let's Encrypt Project",
    license="",
    url="https://letsencrypt.org",
    packages=[
        'letsencrypt',
        'letsencrypt.acme',
        'letsencrypt.client',
        'letsencrypt.client.apache',
        'letsencrypt.client.display',
        'letsencrypt.client.tests',
        'letsencrypt.client.tests.apache',
        'letsencrypt.client.tests.display',
        'letsencrypt.scripts',
    ],
    install_requires=install_requires,
    tests_require=install_requires,
    test_suite='letsencrypt',
    extras_require={
        'dev': dev_extras,
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
