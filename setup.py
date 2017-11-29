import codecs
import os
import re
import sys

from setuptools import setup
from setuptools import find_packages

# Workaround for http://bugs.python.org/issue8876, see
# http://bugs.python.org/issue8876#msg208792
# This can be removed when using Python 2.7.9 or later:
# https://hg.python.org/cpython/raw-file/v2.7.9/Misc/NEWS
if os.path.abspath(__file__).split(os.path.sep)[1] == 'vagrant':
    del os.link


def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()


here = os.path.abspath(os.path.dirname(__file__))

# read version number (and other metadata) from package init
init_fn = os.path.join(here, 'certbot', '__init__.py')
meta = dict(re.findall(r"""__([a-z]+)__ = '([^']+)""", read_file(init_fn)))

readme = read_file(os.path.join(here, 'README.rst'))
changes = read_file(os.path.join(here, 'CHANGES.rst'))
version = meta['version']

# Please update tox.ini when modifying dependency version requirements
# This package relies on requests, however, it isn't specified here to avoid
# masking the more specific request requirements in acme. See
# https://github.com/pypa/pip/issues/988 for more info.
install_requires = [
    'acme=={0}'.format(version),
    # We technically need ConfigArgParse 0.10.0 for Python 2.6 support, but
    # saying so here causes a runtime error against our temporary fork of 0.9.3
    # in which we added 2.6 support (see #2243), so we relax the requirement.
    'ConfigArgParse>=0.9.3',
    'configobj',
    'cryptography>=1.2',  # load_pem_x509_certificate
    'mock',
    'parsedatetime>=1.3',  # Calendar.parseDT
    'PyOpenSSL',
    'pyrfc3339',
    'pytz',
    # For pkg_resources. >=1.0 so pip resolves it to a version cryptography
    # will tolerate; see #2599:
    'setuptools>=1.0',
    'six',
    'zope.component',
    'zope.interface',
]

# env markers cause problems with older pip and setuptools
if sys.version_info < (2, 7):
    install_requires.extend([
        'argparse',
        'ordereddict',
    ])

dev_extras = [
    # Pin astroid==1.3.5, pylint==1.4.2 as a workaround for #289
    'astroid==1.3.5',
    'coverage',
    'ipdb',
    'pytest',
    'pytest-cov',
    'pytest-xdist',
    'pylint==1.4.2',  # upstream #248
    'tox',
    'twine',
    'wheel',
]

docs_extras = [
    'repoze.sphinx.autointerface',
    # autodoc_member_order = 'bysource', autodoc_default_flags, and #4686
    'Sphinx >=1.0,<=1.5.6',
    'sphinx_rtd_theme',
]

setup(
    name='certbot',
    version=version,
    description="ACME client",
    long_description=readme,  # later: + '\n\n' + changes
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Environment :: Console :: Curses',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(exclude=['docs', 'examples', 'tests', 'venv']),
    include_package_data=True,

    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
    },

    # to test all packages run "python setup.py test -s
    # {acme,certbot_apache,certbot_nginx}"
    test_suite='certbot',

    entry_points={
        'console_scripts': [
            'certbot = certbot.main:main',
        ],
        'certbot.plugins': [
            'manual = certbot.plugins.manual:Authenticator',
            'null = certbot.plugins.null:Installer',
            'standalone = certbot.plugins.standalone:Authenticator',
            'webroot = certbot.plugins.webroot:Authenticator',
        ],
    },
)
