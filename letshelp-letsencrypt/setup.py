import sys

from setuptools import setup
from setuptools import find_packages


version = '0.0.0.dev20151008'

install_requires = [
    'setuptools',  # pkg_resources
]
if sys.version_info < (2, 7):
    install_requires.append('mock<1.1.0')
else:
    install_requires.append('mock')

setup(
    name='letshelp-letsencrypt',
    version=version,
    description="Let's help Let's Encrypt client",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Let's Encrypt Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
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
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'letshelp-letsencrypt-apache = letshelp_letsencrypt.apache:main',
        ],
    },
)
