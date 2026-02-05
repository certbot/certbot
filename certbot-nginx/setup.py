from setuptools import setup

version = '5.4.0.dev0'

install_requires = [
    f'certbot[nginx]>={version}',
]

setup(
    version=version,
    install_requires=install_requires,
)
