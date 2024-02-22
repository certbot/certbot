import os
from setuptools import find_packages, setup

version = '2.10.0.dev0'

install_requires = [
    'dns-lexicon>=3.14.1',
    'setuptools>=41.6.0',
]

# Condition simplified to reduce nesting
if not os.environ.get('SNAP_BUILD'):
    install_requires.extend([f'acme>={version}', f'certbot>={version}'])

docs_extras = ['Sphinx>=1.0', 'sphinx_rtd_theme']
test_extras = ['pytest']

setup(
    name='certbot-dns-dnsimple',
    version=version,
    description="DNSimple DNS Authenticator plugin for Certbot",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
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
    extras_require={'docs': docs_extras, 'test': test_extras},
    entry_points={
        'certbot.plugins': ['dns-dnsimple = certbot_dns_dnsimple._internal.dns_dnsimple:Authenticator'],
    },
)
