import sys

from setuptools import setup
from setuptools import find_packages


version = '0.14.0.dev0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'argparse',
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    'cryptography>=0.8',
    # Connection.set_tlsext_host_name (>=0.13)
    'mock',
    'PyOpenSSL>=0.13',
    'pyrfc3339',
    'pytz',
    # requests>=2.10 is required to fix
    # https://github.com/shazow/urllib3/issues/556. This requirement can be
    # relaxed to 'requests[security]>=2.4.1', however, less useful errors
    # will be raised for some network/SSL errors.
    'requests[security]>=2.10',
    # For pkg_resources. >=1.0 so pip resolves it to a version cryptography
    # will tolerate; see #2599:
    'setuptools>=1.0',
    'six',
]

dev_extras = [
    'nose',
    'tox',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]


setup(
    name='acme',
    version=version,
    description='ACME protocol implementation in Python',
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
    },
    entry_points={
        'console_scripts': [
            'jws = acme.jose.jws:CLI.run',
        ],
    },
    test_suite='acme',
)
