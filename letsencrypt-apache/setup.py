import sys

from setuptools import setup
from setuptools import find_packages


version = '0.5.0.dev0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'acme=={0}'.format(version),
    'letsencrypt=={0}'.format(version),
    'python-augeas',
    'setuptools',  # pkg_resources
    'zope.component',
    'zope.interface',
]

if sys.version_info < (2, 7):
    install_requires.append('mock<1.1.0')
else:
    install_requires.append('mock')

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

setup(
    name='letsencrypt-apache',
    version=version,
    description="Apache plugin for Let's Encrypt client",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Let's Encrypt Project",
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
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        'letsencrypt.plugins': [
            'apache = letsencrypt_apache.configurator:ApacheConfigurator',
        ],
    },
    test_suite='letsencrypt_apache',
)
