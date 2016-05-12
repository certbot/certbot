import codecs
import os
import sys

from setuptools import setup
from setuptools import find_packages


def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()


here = os.path.abspath(os.path.dirname(__file__))
readme = read_file(os.path.join(here, 'README.rst'))


version = '0.6.0'


# This package is a simple shim around certbot-apache
install_requires = [
    'certbot-apache',
    'letsencrypt=={0}'.format(version),
]


setup(
    name='letsencrypt-apache',
    version=version,
    description="Apache plugin for Let's Encrypt",
    long_description=readme,
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
)
