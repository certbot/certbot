from distutils.version import LooseVersion
import sys

from setuptools import __version__ as setuptools_version
from setuptools import find_packages
from setuptools import setup

version = '1.12.0'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'acme>=1.4.0',
    'certbot>=1.6.0',
    'PyOpenSSL>=17.3.0',
    'pyparsing>=2.2.0',
    'setuptools>=39.0.1',
    'zope.interface',
]

setuptools_known_environment_markers = (LooseVersion(setuptools_version) >= LooseVersion('36.2'))
if setuptools_known_environment_markers:
    install_requires.append('mock ; python_version < "3.3"')
elif 'bdist_wheel' in sys.argv[1:]:
    raise RuntimeError('Error, you are trying to build certbot wheels using an old version '
                       'of setuptools. Version 36.2+ of setuptools is required.')
elif sys.version_info < (3,3):
    install_requires.append('mock')

setup(
    name='certbot-nginx',
    version=version,
    description="Nginx plugin for Certbot",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
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

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'certbot.plugins': [
            'nginx = certbot_nginx._internal.configurator:NginxConfigurator',
        ],
    },
)
