from setuptools import setup
from setuptools import find_packages


install_requires = [
    'acme',
    'letsencrypt',
    'mock<1.1.0',  # py26
    'python-augeas',
    'setuptools',  # pkg_resources
    'zope.component',
    'zope.interface',
]

setup(
    name='letsencrypt-apache',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'letsencrypt.plugins': [
            'apache = letsencrypt_apache.configurator:ApacheConfigurator',
        ],
    },
    include_package_data=True,
)
