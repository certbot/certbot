from setuptools import setup

version = '5.3.0.dev0'

install_requires = [
    # We specify the minimum acme and certbot version as the current plugin
    # version for simplicity. See
    # https://github.com/certbot/certbot/issues/8761 for more info.
    f'acme>={version}',
    f'certbot>={version}',
    # PyOpenSSL>=25.0.0 is just needed to satisfy mypy right now so this dependency can probably be
    # relaxed to >=24.0.0 if needed.
    'PyOpenSSL>=25.0.0',
    'pyparsing>=2.4.7',
]

setup(
    version=version,
    install_requires=install_requires,
)
