import sys

from setuptools import setup
from setuptools import find_packages


version = '0.33.0.dev0'

install_requires = [
    'certbot',
    'certbot-apache',
    'mock',
    'six',
    'requests',
    'zope.interface',
]

if sys.version_info < (2, 7, 9):
    # For secure SSL connexion with Python 2.7 (InsecurePlatformWarning)
    install_requires.append('ndg-httpsclient')
    install_requires.append('pyasn1')

docs_extras = [
    'repoze.sphinx.autointerface',
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

setup(
    name='certbot-compatibility-test',
    version=version,
    description="Compatibility tests for Certbot",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        'console_scripts': [
            'certbot-compatibility-test = certbot_compatibility_test.test_driver:main',
        ],
    },
)
