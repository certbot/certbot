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
    'parsedatetime>=2.4',
    'pyrfc3339',
    # This dependency needs to be added using environment markers to avoid its
    # installation on Linux.
    'pywin32>=300 ; sys_platform == "win32"',
]


setup(
    install_requires=install_requires,
)
