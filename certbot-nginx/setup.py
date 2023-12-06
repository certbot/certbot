from setuptools import find_packages
from setuptools import setup

version = '2.9.0.dev0'

install_requires = [
    # We specify the minimum acme and certbot version as the current plugin
    # version for simplicity. See
    # https://github.com/certbot/certbot/issues/8761 for more info.
    f'acme>={version}',
    f'certbot>={version}',
    'importlib_resources>=1.3.1; python_version < "3.9"',
    # pyOpenSSL 23.1.0 is a bad release: https://github.com/pyca/pyopenssl/issues/1199
    'PyOpenSSL>=17.5.0,!=23.1.0',
    'pyparsing>=2.2.1',
    'setuptools>=41.6.0',
]

test_extras = [
    'pytest',
]

setup(
    name='certbot-nginx',
    version=version,
    description="Nginx plugin for Certbot",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'test': test_extras,
    },
    entry_points={
        'certbot.plugins': [
            'nginx = certbot_nginx._internal.configurator:NginxConfigurator',
        ],
    },
)
