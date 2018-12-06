from setuptools import setup
from setuptools import find_packages


version = '0.29.1'

# Remember to update local-oldest-requirements.txt when changing the minimum
# acme/certbot version.
install_requires = [
    'acme>=0.26.0',
    'certbot>=0.22.0',
    'mock',
    'PyOpenSSL',
    'pyparsing>=1.5.5',  # Python3 support; perhaps unnecessary?
    'setuptools',
    'zope.interface',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

setup(
    name='certbot-nginx',
    version=version,
    description="Nginx plugin for Certbot",
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
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
        'docs': docs_extras,
    },
    entry_points={
        'certbot.plugins': [
            'nginx = certbot_nginx.configurator:NginxConfigurator',
        ],
    },
    test_suite='certbot_nginx',
)
