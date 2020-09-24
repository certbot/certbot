#!/usr/bin/env python
"""A small script that can act as a trust root for installing pip >=8
Embed this in your project, and your VCS checkout is all you have to trust. In
a post-peep era, this lets you claw your way to a hash-checking version of pip,
with which you can install the rest of your dependencies safely. All it assumes
is Python 2.6 or better and *some* version of pip already installed. If
anything goes wrong, it will exit with a non-zero status code.
"""
# This is here so embedded copies are MIT-compliant:
# Copyright (c) 2016 Erik Rose
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
from __future__ import print_function
from distutils.version import StrictVersion
from hashlib import sha256
from os import environ
from os.path import join
from shutil import rmtree
try:
    from subprocess import check_output
except ImportError:
    from subprocess import CalledProcessError, PIPE, Popen

    def check_output(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be '
                             'overridden.')
        process = Popen(stdout=PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise CalledProcessError(retcode, cmd)
        return output
import sys
from tempfile import mkdtemp
try:
    from urllib2 import build_opener, HTTPHandler, HTTPSHandler
except ImportError:
    from urllib.request import build_opener, HTTPHandler, HTTPSHandler
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse  # 3.4


__version__ = 1, 5, 1
PIP_VERSION = '9.0.1'
DEFAULT_INDEX_BASE = 'https://pypi.python.org'


# wheel has a conditional dependency on argparse:
maybe_argparse = (
    [('18/dd/e617cfc3f6210ae183374cd9f6a26b20514bbb5a792af97949c5aacddf0f/'
      'argparse-1.4.0.tar.gz',
      '62b089a55be1d8949cd2bc7e0df0bddb9e028faefc8c32038cc84862aefdd6e4')]
    if sys.version_info < (2, 7, 0) else [])


# Be careful when updating the pinned versions here, in particular for pip.
# Indeed starting from 10.0, pip will build dependencies in isolation if the
# related projects are compliant with PEP 517. This is not something we want
# as of now, so the isolation build will need to be disabled wherever
# pipstrap is used (see https://github.com/certbot/certbot/issues/8256).
PACKAGES = maybe_argparse + [
    # Pip has no dependencies, as it vendors everything:
    ('11/b6/abcb525026a4be042b486df43905d6893fb04f05aac21c32c638e939e447/'
     'pip-{0}.tar.gz'.format(PIP_VERSION),
     '09f243e1a7b461f654c26a725fa373211bb7ff17a9300058b205c61658ca940d'),
    # This version of setuptools has only optional dependencies:
    ('37/1b/b25507861991beeade31473868463dad0e58b1978c209de27384ae541b0b/'
     'setuptools-40.6.3.zip',
     '3b474dad69c49f0d2d86696b68105f3a6f195f7ab655af12ef9a9c326d2b08f8'),
    ('c9/1d/bd19e691fd4cfe908c76c429fe6e4436c9e83583c4414b54f6c85471954a/'
     'wheel-0.29.0.tar.gz',
     '1ebb8ad7e26b448e9caa4773d2357849bf80ff9e313964bcaf79cbf0201a1648')
]


class HashError(Exception):
    def __str__(self):
        url, path, actual, expected = self.args
        return ('{url} did not match the expected hash {expected}. Instead, '
                'it was {actual}. The file (left at {path}) may have been '
                'tampered with.'.format(**locals()))


def hashed_download(url, temp, digest):
    """Download ``url`` to ``temp``, make sure it has the SHA-256 ``digest``,
    and return its path."""
    # Based on pip 1.4.1's URLOpener but with cert verification removed. Python
    # >=2.7.9 verifies HTTPS certs itself, and, in any case, the cert
    # authenticity has only privacy (not arbitrary code execution)
    # implications, since we're checking hashes.
    def opener(using_https=True):
        opener = build_opener(HTTPSHandler())
        if using_https:
            # Strip out HTTPHandler to prevent MITM spoof:
            for handler in opener.handlers:
                if isinstance(handler, HTTPHandler):
                    opener.handlers.remove(handler)
        return opener

    def read_chunks(response, chunk_size):
        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            yield chunk

    parsed_url = urlparse(url)
    response = opener(using_https=parsed_url.scheme == 'https').open(url)
    path = join(temp, parsed_url.path.split('/')[-1])
    actual_hash = sha256()
    with open(path, 'wb') as file:
        for chunk in read_chunks(response, 4096):
            file.write(chunk)
            actual_hash.update(chunk)

    actual_digest = actual_hash.hexdigest()
    if actual_digest != digest:
        raise HashError(url, path, actual_digest, digest)
    return path


def get_index_base():
    """Return the URL to the dir containing the "packages" folder.
    Try to wring something out of PIP_INDEX_URL, if set. Hack "/simple" off the
    end if it's there; that is likely to give us the right dir.
    """
    env_var = environ.get('PIP_INDEX_URL', '').rstrip('/')
    if env_var:
        SIMPLE = '/simple'
        if env_var.endswith(SIMPLE):
            return env_var[:-len(SIMPLE)]
        else:
            return env_var
    else:
        return DEFAULT_INDEX_BASE


def main():
    python = sys.executable or 'python'
    pip_version = StrictVersion(check_output([python, '-m', 'pip', '--version'])
                                .decode('utf-8').split()[1])
    has_pip_cache = pip_version >= StrictVersion('6.0')
    index_base = get_index_base()
    temp = mkdtemp(prefix='pipstrap-')
    try:
        downloads = [hashed_download(index_base + '/packages/' + path,
                                     temp,
                                     digest)
                     for path, digest in PACKAGES]
        # Calling pip as a module is the preferred way to avoid problems about pip self-upgrade.
        command = [python, '-m', 'pip', 'install', '--no-index', '--no-deps', '-U']
        # Disable cache since it is not used and it otherwise sometimes throws permission warnings:
        command.extend(['--no-cache-dir'] if has_pip_cache else [])
        command.extend(downloads)
        check_output(command)
    except HashError as exc:
        print(exc)
    except Exception:
        rmtree(temp)
        raise
    else:
        rmtree(temp)
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
