from setuptools import find_packages
from setuptools import setup

version = '5.0.0.dev0'

install_requires = [
    # We specify the minimum acme and certbot version as the current plugin
    # version for simplicity. See
    # https://github.com/certbot/certbot/issues/8761 for more info.
    f'acme>={version}',
    f'certbot>={version}',
    'python-augeas',
]

dev_extras = [
    'apacheconfig>=0.3.2',
]

test_extras = [
    'pytest',
]

setup(
    name='certbot-apache',
    version=version,
    description="Apache plugin for Certbot",
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.10',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'test': test_extras,
    },
    entry_points={
        'certbot.plugins': [
            'apache = certbot_apache._internal.entrypoint:ENTRYPOINT',
        ],
    },
)
