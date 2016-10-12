import sys

from setuptools import setup
from setuptools import find_packages


version = '0.9.2'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    'cryptography>=0.8',
    'ndg-httpsclient',  # urllib3 InsecurePlatformWarning (#304)
    'pyasn1',  # urllib3 InsecurePlatformWarning (#304)
    # Connection.set_tlsext_host_name (>=0.13)
    'PyOpenSSL>=0.13',
    'pyrfc3339',
    'pytz',
    'requests',
    # For pkg_resources. >=1.0 so pip resolves it to a version cryptography
    # will tolerate; see #2599:
    'setuptools>=1.0',
    'six',
]

# env markers in extras_require cause problems with older pip: #517
# Keep in sync with conditional_requirements.py.
if sys.version_info < (2, 7):
    install_requires.extend([
        # only some distros recognize stdlib argparse as already satisfying
        'argparse',
        'mock<1.1.0',
    ])
else:
    install_requires.append('mock')

# dnspython 1.12 is required to support both Python 2 and Python 3.
dns_extras = [
    'dnspython>=1.12',
]

dev_extras = [
    'nose',
    'pep8',
    'tox',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
    'sphinxcontrib-programoutput',
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
        'dns': dns_extras,
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
