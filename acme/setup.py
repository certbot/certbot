from setuptools import setup
from setuptools import find_packages


install_requires = [
    'argparse',
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    'cryptography>=0.8',
    'mock<1.1.0',  # py26
    'pyrfc3339',
    'ndg-httpsclient',  # urllib3 InsecurePlatformWarning (#304)
    'pyasn1',  # urllib3 InsecurePlatformWarning (#304)
    'PyOpenSSL',
    'pytz',
    'requests',
    'werkzeug',
]

setup(
    name='acme',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'jws = acme.jose.jws:CLI.run',
        ],
    },
)
