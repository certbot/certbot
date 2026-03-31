import codecs
import os
import re

from setuptools import setup


def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()


here = os.path.abspath(os.path.dirname(__file__))

# read version number (and other metadata) from package init
init_fn = os.path.join(here, 'src', 'certbot', '__init__.py')
meta = dict(re.findall(r"""__([a-z]+)__ = '([^']+)""", read_file(init_fn)))

version = meta['version']

# This package relies on PyOpenSSL and requests, however, it isn't specified
# here to avoid masking the more specific request requirements in acme. See
# https://github.com/pypa/pip/issues/988 for more info.
install_requires = [
    # We specify the minimum acme version as the current Certbot version for
    # simplicity. See https://github.com/certbot/certbot/issues/8761 for more
    # info.
    f'acme>={version}',
    'ConfigArgParse>=1.5.3',
    'configobj>=5.0.6',
    'cryptography>=43.0.0',
    'distro>=1.0.1',
    'importlib_metadata>=8.6.1; python_version < "3.10"',
    'josepy>=2.0.0',
    'parsedatetime>=2.6',
    'pyrfc3339',
    # This dependency needs to be added using environment markers to avoid its
    # installation on Linux.
    'pywin32>=300 ; sys_platform == "win32"',
]

extras_require = {
    "dev": [
        "apacheconfig>=0.3.2",
        "azure-devops",
        "build",
        "ipdb",
        # allows us to use newer urllib3 https://github.com/python-poetry/poetry-plugin-export/issues/183
        "poetry-plugin-export>=1.9.0",
        # poetry 1.2.0+ is required for it to pin pip, setuptools, and wheel. See
        # https://github.com/python-poetry/poetry/issues/1584.
        "poetry>=1.2.0",
        "towncrier",
        "twine",
    ],
    "docs": [
        # If you have Sphinx<1.5.1, you need docutils<0.13.1
        # https://github.com/sphinx-doc/sphinx/issues/3212
        "Sphinx>=1.2", # Annotation support
        "sphinx_rtd_theme",
    ],
    # Tools like pip, wheel, and tox are listed here to ensure they are properly
    # pinned and installed during automated testing.
    "test": [
        "coverage",
        "mypy",
        "pip",
        "pylint",
        "pytest",
        "pytest-cov>=4.1.0", # https://github.com/pytest-dev/pytest-cov/pull/558
        "pytest-xdist",
        "ruff",
        "setuptools",
        "tox",
        "types-httplib2",
        "types-pyRFC3339",
        "types-pywin32",
        "types-requests",
        "types-setuptools",
        "uv",
        "wheel",
    ],
    "apache":  [
        # If a user installs `certbot[apache]`, we want to include the shim
        f'certbot-apache>={version}',
        'python-augeas',
    ],
    "nginx": [
        # If a user installs `certbot[nginx]`, we want to include the shim
        f'certbot-nginx>={version}',
        # PyOpenSSL>=25.0.0 is just needed to satisfy mypy right now so this dependency can probably be
        # relaxed to >=24.0.0 if needed.
        'PyOpenSSL>=25.0.0',
        'pyparsing>=3.0.0',
    ],
    "all": [
        "certbot[dev,docs,test,apache,nginx]"
    ],
}


setup(
    install_requires=install_requires,
    extras_require=extras_require,
)
