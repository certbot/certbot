"""Setup script for certbot-consul"""

from setuptools import find_packages, setup

version = '1.22.0.dev0'

setup(
    name='certbot-consul',
    version=version,
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=[
        f'certbot>={version}',
        'python-consul>=1.1.0',
        'setuptools>=39.0.1',
    ],
    entry_points={
        'certbot.plugins': [
            'consul = cert_consul:Installer',
        ],
    },
)
