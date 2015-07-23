from setuptools import setup
from setuptools import find_packages


install_requires = [
    'letsencrypt',
    'letsencrypt-apache',
    'letsencrypt-nginx',
    'docker-py',
    'mock<1.1.0',  # py26
    'zope.interface',
]

setup(
    name='compatibility-test',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'compatibility-test = compatibility.test_driver:main',
        ],
    },
)
