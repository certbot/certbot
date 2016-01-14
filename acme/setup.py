import sys

from setuptools import setup
from setuptools import find_packages


version = '0.2.0.dev0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    'cryptography>=0.8',
    # Connection.set_tlsext_host_name (>=0.13)
    'PyOpenSSL>=0.13',
    'pyrfc3339',
    'pytz',
    'requests',
    'setuptools',  # pkg_resources
    'six',
    'werkzeug',
]

# env markers in extras_require cause problems with older pip: #517
# Keep in sync with conditional_requirements.py.
if sys.version_info < (2, 7):
    install_requires.extend([
        # only some distros recognize stdlib argparse as already satisfying
        'argparse',
    ])

# Keep in sync with conditional_requirements.py.
if sys.version_info < (2, 7, 9):
    # For secure SSL connection with Python 2.7 (InsecurePlatformWarning)
    install_requires.append('ndg-httpsclient')
    install_requires.append('pyasn1')

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
    'sphinxcontrib-programoutput',
]

testing_extras = [
    'nose',
    'tox',
]


setup(
    name='acme',
    version=version,
    description='ACME protocol implementation in Python',
    url='https://github.com/letsencrypt/letsencrypt',
    author="Let's Encrypt Project",
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
    tests_require='mock<1.1.0' if sys.version_info < (2, 7) else 'mock',
    extras_require={
        'docs': docs_extras,
        'testing': testing_extras,
    },
    entry_points={
        'console_scripts': [
            'jws = acme.jose.jws:CLI.run',
        ],
    },
    test_suite='acme',
)
