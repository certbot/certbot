from setuptools import setup
from setuptools import find_packages


version = '0.1.0.dev0'

install_requires = [
    'acme=={0}'.format(version),
    'letsencrypt=={0}'.format(version),
    'mock<1.1.0',  # py26
    'PyOpenSSL',
    'pyparsing>=1.5.5',  # Python3 support; perhaps unnecessary?
    'setuptools',  # pkg_resources
    'zope.interface',
]

setup(
    name='letsencrypt-nginx',
    version=version,
    description="Nginx plugin for Let's Encrypt client",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Let's Encrypt Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',

    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'letsencrypt.plugins': [
            'nginx = letsencrypt_nginx.configurator:NginxConfigurator',
        ],
    },
    include_package_data=True,
)
