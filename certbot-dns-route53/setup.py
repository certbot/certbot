import sys

from distutils.core import setup
from setuptools import find_packages

version = '0.16.0.dev0'

install_requires = [
    'acme=={0}'.format(version),
    'certbot=={0}'.format(version),
    'boto3',
    'mock',
    # For pkg_resources. >=1.0 so pip resolves it to a version cryptography
    # will tolerate; see #2599:
    'setuptools>=1.0',
    'zope.interface',
]

setup(
    name='certbot-dns-route53',
    version=version,
    description="Route53 DNS Authenticator plugin for Certbot",
    url='https://github.com/certbot/certbot',
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
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    keywords=['certbot', 'route53', 'aws'],
    entry_points={
        'certbot.plugins': [
            'dns-route53 = certbot_dns_route53.dns_route53:Authenticator',
            'certbot-route53:auth = certbot_dns_route53.authenticator:Authenticator'
        ],
    },
    test_suite='certbot_dns_route53',
)
