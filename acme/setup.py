import sys

from setuptools import find_packages
from setuptools import setup

version = '1.14.0.dev0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'cryptography>=2.1.4',
    # formerly known as acme.jose:
    # 1.1.0+ is required to avoid the warnings described at
    # https://github.com/certbot/josepy/issues/13.
    'josepy>=1.1.0',
    'PyOpenSSL>=17.3.0',
    'pyrfc3339',
    'pytz',
    'requests>=2.6.0',
    'requests-toolbelt>=0.3.0',
    'setuptools>=39.0.1',
]

dev_extras = [
    'pytest',
    'pytest-xdist',
    'tox',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

setup(
    name='acme',
    version=version,
    description='ACME protocol implementation in Python',
    url='https://github.com/letsencrypt/letsencrypt',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
    },
)
