import sys

from setuptools import find_packages
from setuptools import setup

version = '3.1.0.dev0'

install_requires = [
    'cryptography>=3.2.1',
    # Josepy 2+ may introduce backward incompatible changes by droping usage of
    # deprecated PyOpenSSL APIs.
    'josepy>=1.13.0, <2',
    # pyOpenSSL 23.1.0 is a bad release: https://github.com/pyca/pyopenssl/issues/1199
    'PyOpenSSL>=17.5.0,!=23.1.0',
    'pyrfc3339',
    'pytz>=2019.3',
    'requests>=2.20.0',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

test_extras = [
    # In theory we could scope importlib_resources to env marker 'python_version<"3.9"'. But this
    # makes the pinning mechanism emit warnings when running `poetry lock` because in the corner
    # case of an extra dependency with env marker coming from a setup.py file, it generate the
    # invalid requirement 'importlib_resource>=1.3.1;python<=3.9;extra=="test"'.
    # To fix the issue, we do not pass the env marker. This is fine because:
    # - importlib_resources can be applied to any Python version,
    # - this is a "test" extra dependency for limited audience,
    # - it does not change anything at the end for the generated requirement files.
    'importlib_resources>=1.3.1',
    'pytest',
    'pytest-xdist',
    'typing-extensions',
]

setup(
    name='acme',
    version=version,
    description='ACME protocol implementation in Python',
    url='https://github.com/certbot/certbot',
    author="Certbot Project",
    author_email='certbot-dev@eff.org',
    license='Apache License 2.0',
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
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
