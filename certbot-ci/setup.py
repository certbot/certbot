from distutils.version import StrictVersion
import sys

from setuptools import __version__ as setuptools_version
from setuptools import find_packages
from setuptools import setup

version = '0.32.0.dev0'

install_requires = [
    'coverage',
    'cryptography',
    'docker-compose',
    'pyopenssl',
    'pytest',
    'pytest-cov',
    'pytest-xdist',
    'python-dateutil',
    'pyyaml',
    'requests',
    'six',
]

# Add pywin32 on Windows platforms to handle low-level system calls.
# This dependency needs to be added using environment markers to avoid its installation on Linux.
# However environment markers are supported only with setuptools >= 36.2.
# So this dependency is not added for old Linux distributions with old setuptools,
# in order to allow these systems to build certbot from sources.
if StrictVersion(setuptools_version) >= StrictVersion('36.2'):
    install_requires.append("pywin32>=224 ; sys_platform == 'win32'")
elif 'bdist_wheel' in sys.argv[1:]:
    raise RuntimeError('Error, you are trying to build certbot wheels using an old version '
                       'of setuptools. Version 36.2+ of setuptools is required.')

setup(
    name='certbot-ci',
    version=version,
    description="Certbot continuous integration framework",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
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
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,

    entry_points={
        'console_scripts': [
            'certbot_test=certbot_integration_tests.utils.certbot_call:main',
            'run_acme_server=certbot_integration_tests.utils.acme_server:main',
        ],
    }
)
