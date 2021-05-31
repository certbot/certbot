import sys

from setuptools import find_packages
from setuptools import setup

version = '1.16.0.dev0'

if sys.platform == 'win32':
    # On Windows, makes certbot-apache essentially an empty project to avoid any
    # problem at build time or run time with python-augeas
    packages = []
    install_requires = []
    extra_require = {'dev': []}
    entry_points = {}
else:
    packages = find_packages()
    # Remember to update local-oldest-requirements.txt when changing the minimum
    # acme/certbot version.
    install_requires = [
        'acme>=1.8.0',
        'certbot>=1.10.1',
        'python-augeas',
        'setuptools>=39.0.1',
        'zope.component',
        'zope.interface',
    ]
    extra_require = {
        'dev': [
            'apacheconfig>=0.3.2',
        ],
    }
    entry_points = {
        'certbot.plugins': [
            'apache = certbot_apache._internal.entrypoint:ENTRYPOINT',
        ],
    }

setup(
    name='certbot-apache',
    version=version,
    description="Apache plugin for Certbot",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=packages,
    include_package_data=True,
    install_requires=install_requires,
    extras_require=extra_require,
    entry_points=entry_points,
)
