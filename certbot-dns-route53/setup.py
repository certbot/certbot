from setuptools import setup
from setuptools import find_packages

version = '0.26.0.dev0'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'acme>0.24.0',
    'certbot>=0.21.1',
    'boto3',
    'mock',
    'setuptools',
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
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
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
