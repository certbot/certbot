import sys

from distutils.core import setup
from setuptools import find_packages

version = '0.1.5'

install_requires = [
    'acme>=0.9.0',
    'certbot>=0.9.0',
    'zope.interface',
    'boto3',
]

setup(
    name='certbot-route53',
    version=version,
    description="Route53 plugin for certbot",
    url='https://github.com/lifeonmarspt/certbot-route53',
    author="Hugo Peixoto",
    author_email='hugo@lifeonmars.pt',
    license='Apache2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
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
    packages=find_packages(),
    install_requires=install_requires,
    keywords=['certbot', 'route53', 'aws'],
    entry_points={
        'certbot.plugins': [
            'auth = certbot_route53.authenticator:Authenticator'
        ],
    },
)
