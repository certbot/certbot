import os
import sys

from setuptools import find_packages
from setuptools import setup

version = '2.4.0.dev0'

install_requires = [
    # This version of lexicon is required to address the problem described in
    # https://github.com/AnalogJ/lexicon/issues/387.
    'dns-lexicon>=3.2.1',
    'setuptools>=41.6.0',
]

if not os.environ.get('SNAP_BUILD'):
    install_requires.extend([
        # We specify the minimum acme and certbot version as the current plugin
        # version for simplicity. See
        # https://github.com/certbot/certbot/issues/8761 for more info.
        f'acme>={version}',
        f'certbot>={version}',
    ])
elif 'bdist_wheel' in sys.argv[1:]:
    raise RuntimeError('Unset SNAP_BUILD when building wheels '
                       'to include certbot dependencies.')
if os.environ.get('SNAP_BUILD'):
    install_requires.append('packaging')

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

test_extras = [
    'pytest',
]

setup(
    name='certbot-dns-dnsimple',
    version=version,
    description="DNSimple DNS Authenticator plugin for Certbot",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
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
        'test': test_extras,
    },
    entry_points={
        'certbot.plugins': [
            'dns-dnsimple = certbot_dns_dnsimple._internal.dns_dnsimple:Authenticator',
        ],
    },
)
