import sys

from setuptools import find_packages
from setuptools import setup

version = '1.29.0.dev0'

install_requires = [
    'cryptography>=2.5.0',
    'josepy>=1.13.0',
    'PyOpenSSL>=17.5.0',
    'pyrfc3339',
    'pytz>=2019.3',
    'requests>=2.20.0',
    'requests-toolbelt>=0.3.0',
    'setuptools>=41.6.0',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

test_extras = [
    'pytest',
    'pytest-xdist',
    'typing-extensions',
]

setup(
    name='acme',
    version=version,
    description='ACME protocol implementation in Python',
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
        'test': test_extras,
    },
)
