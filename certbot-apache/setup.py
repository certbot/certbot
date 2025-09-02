from setuptools import setup

version = '5.1.0.dev0'

install_requires = [
    # We specify the minimum acme and certbot version as the current plugin
    # version for simplicity. See
    # https://github.com/certbot/certbot/issues/8761 for more info.
    f'acme>={version}',
    f'certbot>={version}',
    'python-augeas',
]

setup(
    version=version,
    install_requires=install_requires,
)
