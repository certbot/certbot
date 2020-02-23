import os
import sys

from setuptools import find_packages
from setuptools import setup
from setuptools.command.test import test as TestCommand

version = '1.3.0.dev0'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'acme>=0.31.0',
    'certbot>=1.1.0',
    'mock',
    'setuptools',
    'zope.interface',
]

# This package normally depends on dns-lexicon>=3.2.1 to address the
# problem described in https://github.com/AnalogJ/lexicon/issues/387,
# however, the fix there has been backported to older versions of
# lexicon found in various Linux distros. This conditional helps us test
# that we've maintained compatibility with these versions of lexicon
# which allows us to potentially upgrade our packages in these distros
# as necessary.
if os.environ.get('CERTBOT_OLDEST') == '1':
    install_requires.append('dns-lexicon>=2.2.1')
else:
    install_requires.append('dns-lexicon>=3.2.1')

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

class PyTest(TestCommand):
    user_options = []

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = ''

    def run_tests(self):
        import shlex
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(shlex.split(self.pytest_args))
        sys.exit(errno)

setup(
    name='certbot-dns-dnsimple',
    version=version,
    description="DNSimple DNS Authenticator plugin for Certbot",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
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
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        'certbot.plugins': [
            'dns-dnsimple = certbot_dns_dnsimple._internal.dns_dnsimple:Authenticator',
        ],
    },
    tests_require=["pytest"],
    test_suite='certbot_dns_dnsimple',
    cmdclass={"test": PyTest},
)
