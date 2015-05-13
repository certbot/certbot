import codecs
import os
import re

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
meta = dict(re.findall(r"""__([a-z]+)__ = "([^"]+)""", read_file(init_fn)))

readme = read_file(os.path.join(here, 'README.rst'))
changes = read_file(os.path.join(here, 'CHANGES.rst'))

# #358: acme, letsencrypt, letsencrypt_apache, letsencrypt_nginx, etc.
# shall be distributed separately. Please make sure to keep the
# dependecy lists up to date: this is being somewhat checked below
# using an assert statement! Separate lists are helpful for OS package
# maintainers. and will make the future migration a lot easier.
acme_install_requires = [
    'argparse',
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    'cryptography>=0.8',
    #'letsencrypt'  # TODO: uses testdata vectors
    'mock',
    'pyrfc3339',
    'ndg-httpsclient',  # urllib3 InsecurePlatformWarning (#304)
    'pyasn1',  # urllib3 InsecurePlatformWarning (#304)
    #'PyOpenSSL',  # version pin would cause mismatch
    'pytz',
    'requests',
    'werkzeug',
]
letsencrypt_install_requires = [
    #'acme',
    'argparse',
    'ConfigArgParse',
    'configobj',
    'M2Crypto',
    'mock',
    'parsedatetime',
    'psutil>=2.1.0',  # net_connections introduced in 2.1.0
    'pycrypto',
    # https://pyopenssl.readthedocs.org/en/latest/api/crypto.html#OpenSSL.crypto.X509Req.get_extensions
    'PyOpenSSL>=0.15',
    'pyrfc3339',
    'python2-pythondialog>=3.2.2rc1',  # Debian squeeze support, cf. #280
    'pytz',
    'zope.component',
    'zope.interface',
    'M2Crypto',
]
letsencrypt_apache_install_requires = [
    #'acme',
    #'letsencrypt',
    'mock',
    'python-augeas',
    'zope.component',
    'zope.interface',
]
letsencrypt_nginx_install_requires = [
    #'acme',
    #'letsencrypt',
    'pyparsing>=1.5.5',  # Python3 support; perhaps unnecessary?
    'mock',
    'zope.interface',
]

install_requires = [
    'argparse',
    'cryptography>=0.8',
    'ConfigArgParse',
    'configobj',
    'mock',
    'ndg-httpsclient',  # urllib3 InsecurePlatformWarning (#304)
    'parsedatetime',
    'psutil>=2.1.0',  # net_connections introduced in 2.1.0
    'pyasn1',  # urllib3 InsecurePlatformWarning (#304)
    'pycrypto',
    # https://pyopenssl.readthedocs.org/en/latest/api/crypto.html#OpenSSL.crypto.X509Req.get_extensions
    'PyOpenSSL>=0.15',
    'pyparsing>=1.5.5',  # Python3 support; perhaps unnecessary?
    'pyrfc3339',
    'python-augeas',
    'python2-pythondialog>=3.2.2rc1',  # Debian squeeze support, cf. #280
    'pytz',
    'requests',
    'werkzeug',
    'zope.component',
    'zope.interface',
    # order of items in install_requires DOES matter and M2Crypto has
    # to go last, see #152
    'M2Crypto',
]

assert set(install_requires) == set.union(*(set(ireq) for ireq in (
    acme_install_requires,
    letsencrypt_install_requires,
    letsencrypt_apache_install_requires,
    letsencrypt_nginx_install_requires
))), "*install_requires don't match up!"

dev_extras = [
    # Pin astroid==1.3.5, pylint==1.4.2 as a workaround for #289
    'astroid==1.3.5',
    'pylint==1.4.2',  # upstream #248
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
    name='letsencrypt',
    version=meta['version'],
    description="Let's Encrypt",
    long_description=readme,  # later: + '\n\n' + changes
    author="Let's Encrypt Project",
    license='Apache License 2.0',
    url='https://letsencrypt.org',
    classifiers=[
        'Environment :: Console',
        'Environment :: Console :: Curses',
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

    packages=find_packages(exclude=['docs', 'examples', 'tests', 'venv']),
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
            'jws = letsencrypt.acme.jose.jws:CLI.run',
        ],
        'letsencrypt.plugins': [
            'manual = letsencrypt.plugins.manual:ManualAuthenticator',
            # TODO: null should probably not be presented to the user
            'null = letsencrypt.plugins.null:Installer',
            'standalone = letsencrypt.plugins.standalone.authenticator'
            ':StandaloneAuthenticator',

            # to be moved to separate pypi packages
            'apache = letsencrypt_apache.configurator:ApacheConfigurator',
            'nginx = letsencrypt_nginx.configurator:NginxConfigurator',
        ],
    },

    zip_safe=False,
    include_package_data=True,
)
