import sys

from setuptools import setup
from setuptools import find_packages


version = '0.15.0.dev0'

install_requires = [
    'acme=={0}'.format(version),
    'certbot=={0}'.format(version),
    'dnspython',
    'mock',
    'setuptools>=1.0',
    'zope.interface',
]

docs_extras = [
    'Sphinx>=1.0',
    'sphinx_rtd_theme',
]

setup(
    name='certbot-dns-rfc2136',
    version=version,
    description="RFC 2136 DNS Authenticator plugin for Certbot",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        'certbot.plugins': [
            'dns-rfc2136 = certbot_dns_rfc2136.dns_rfc2136:Authenticator',
        ],
    },
    test_suite='certbot_dns_rfc2136',
)
