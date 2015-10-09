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
init_fn = os.path.join(here, 'letsencrypt', '__init__.py')
meta = dict(re.findall(r"""__([a-z]+)__ = '([^']+)""", read_file(init_fn)))

readme = read_file(os.path.join(here, 'README.rst'))
changes = read_file(os.path.join(here, 'CHANGES.rst'))
version = meta['version']

install_requires = [
    'acme=={0}'.format(version),
    'ConfigArgParse',
    'configobj',
    'cryptography>=0.7',  # load_pem_x509_certificate
    'parsedatetime',
    'psutil>=2.1.0',  # net_connections introduced in 2.1.0
    'PyOpenSSL',
    'pyrfc3339',
    'python2-pythondialog>=3.2.2rc1',  # Debian squeeze support, cf. #280
    'pytz',
    'requests',
    'setuptools',  # pkg_resources
    'zope.component',
    'zope.interface',
]

# env markers in extras_require cause problems with older pip: #517
if sys.version_info < (2, 7):
    install_requires.extend([
        # only some distros recognize stdlib argparse as already satisfying
        'argparse',
        'mock<1.1.0',
    ])
else:
    install_requires.append('mock')

dev_extras = [
    # Pin astroid==1.3.5, pylint==1.4.2 as a workaround for #289
    'astroid==1.3.5',
    'pylint==1.4.2',  # upstream #248
    'twine',
    'wheel',
]

docs_extras = [
    'repoze.sphinx.autointerface',
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
    'sphinxcontrib-programoutput',
]

testing_extras = [
    'coverage',
    'nose',
    'nosexcover',
    'pep8',
    'tox',
]

setup(
    name='letsencrypt',
    version=version,
    description="Let's Encrypt client",
    long_description=readme,  # later: + '\n\n' + changes
    url='https://github.com/letsencrypt/letsencrypt',
    author="Let's Encrypt Project",
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
        'Programming Language :: Python :: 2.7',
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
        'testing': testing_extras,
    },

    tests_require=install_requires,
    # to test all packages run "python setup.py test -s
    # {acme,letsencrypt_apache,letsencrypt_nginx}"
    test_suite='letsencrypt',

    entry_points={
        'console_scripts': [
            'letsencrypt = letsencrypt.cli:main',
            'letsencrypt-renewer = letsencrypt.renewer:main',
        ],
        'letsencrypt.plugins': [
            'manual = letsencrypt.plugins.manual:Authenticator',
            'null = letsencrypt.plugins.null:Installer',
            'standalone = letsencrypt.plugins.standalone.authenticator'
            ':StandaloneAuthenticator',
        ],
    },
)
