from setuptools import find_packages
from setuptools import setup

version = '2.0.0.dev0'

install_requires = [
    # We specify the minimum acme and certbot version as the current plugin
    # version for simplicity. See
    # https://github.com/certbot/certbot/issues/8761 for more info.
    f'acme>={version}',
    f'certbot>={version}',
    'PyOpenSSL>=17.5.0',
    'pyparsing>=2.2.1',
    'setuptools>=41.6.0',
]

setup(
    name='certbot-nginx',
    version=version,
    description="Nginx plugin for Certbot",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
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
    entry_points={
        'certbot.plugins': [
            'nginx = certbot_nginx._internal.configurator:NginxConfigurator',
        ],
    },
)
