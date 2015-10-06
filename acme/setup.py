import sys

from setuptools import setup
from setuptools import find_packages


version = '0.0.0.dev20151006'

install_requires = [
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    'cryptography>=0.8',
    'mock<1.1.0',  # py26
    'ndg-httpsclient',  # urllib3 InsecurePlatformWarning (#304)
    'pyasn1',  # urllib3 InsecurePlatformWarning (#304)
    # Connection.set_tlsext_host_name (>=0.13), X509Req.get_extensions (>=0.15)
    'PyOpenSSL>=0.15',
    'pyrfc3339',
    'pytz',
    'requests',
    'setuptools',  # pkg_resources
    'six',
    'werkzeug',
]

# env markers in extras_require cause problems with older pip: #517
if sys.version_info < (2, 7):
    # only some distros recognize stdlib argparse as already satisfying
    install_requires.append('argparse')

testing_extras = [
    'nose',
    'tox',
]


setup(
    name='acme',
    version=version,
    description='ACME protocol implementation',
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
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'testing': testing_extras,
    },
    entry_points={
        'console_scripts': [
            'jws = acme.jose.jws:CLI.run',
        ],
    },
    test_suite='acme',
)
