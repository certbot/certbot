"""Do downloading and JSON parsing without additional dependencies. ::

    # Print latest released version of LE to stdout:
    python fetch.py --latest-version

    # Download letsencrypt-auto script from git tag v1.2.3 into the folder I'm
    # in, and make sure its signature verifies:
    python fetch.py --le-auto-script v1.2.3

On failure, return non-zero.

"""

from __future__ import print_function

from distutils.version import LooseVersion
from json import loads
from os import devnull, environ
from os.path import dirname, join
import re
from subprocess import check_call, CalledProcessError
from sys import argv, exit
from urllib2 import build_opener, HTTPHandler, HTTPSHandler, HTTPError

PUBLIC_KEY = environ.get('LE_AUTO_PUBLIC_KEY', """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6MR8W/galdxnpGqBsYbq
OzQb2eyW15YFjDDEMI0ZOzt8f504obNs920lDnpPD2/KqgsfjOgw2K7xWDJIj/18
xUvWPk3LDkrnokNiRkA3KOx3W6fHycKL+zID7zy+xZYBuh2fLyQtWV1VGQ45iNRp
9+Zo7rH86cdfgkdnWTlNSHyTLW9NbXvyv/E12bppPcEvgCTAQXgnDVJ0/sqmeiij
n9tTFh03aM+R2V/21h8aTraAS24qiPCz6gkmYGC8yr6mglcnNoYbsLNYZ69zF1XH
cXPduCPdPdfLlzVlKK1/U7hkA28eG3BIAMh6uJYBRJTpiGgaGdPd7YekUB8S6cy+
CQIDAQAB
-----END PUBLIC KEY-----
""")

class ExpectedError(Exception):
    """A novice-readable exception that also carries the original exception for
    debugging"""


class HttpsGetter(object):
    def __init__(self):
        """Build an HTTPS opener."""
        # Based on pip 1.4.1's URLOpener
        # This verifies certs on only Python >=2.7.9.
        self._opener = build_opener(HTTPSHandler())
        # Strip out HTTPHandler to prevent MITM spoof:
        for handler in self._opener.handlers:
            if isinstance(handler, HTTPHandler):
                self._opener.handlers.remove(handler)

    def get(self, url):
        """Return the document contents pointed to by an HTTPS URL.

        If something goes wrong (404, timeout, etc.), raise ExpectedError.

        """
        try:
            return self._opener.open(url).read()
        except (HTTPError, IOError) as exc:
            raise ExpectedError("Couldn't download %s." % url, exc)


def write(contents, dir, filename):
    """Write something to a file in a certain directory."""
    with open(join(dir, filename), 'w') as file:
        file.write(contents)


def latest_stable_version(get):
    """Return the latest stable release of letsencrypt."""
    metadata = loads(get(
        environ.get('LE_AUTO_JSON_URL',
                    'https://pypi.python.org/pypi/certbot/json')))
    # metadata['info']['version'] actually returns the latest of any kind of
    # release release, contrary to https://wiki.python.org/moin/PyPIJSON.
    # The regex is a sufficient regex for picking out prereleases for most
    # packages, LE included.
    return str(max(LooseVersion(r) for r
                   in metadata['releases'].iterkeys()
                   if re.match('^[0-9.]+$', r)))


def verified_new_le_auto(get, tag, temp_dir):
    """Return the path to a verified, up-to-date letsencrypt-auto script.

    If the download's signature does not verify or something else goes wrong
    with the verification process, raise ExpectedError.

    """
    le_auto_dir = environ.get(
        'LE_AUTO_DIR_TEMPLATE',
        'https://raw.githubusercontent.com/certbot/certbot/%s/'
        'letsencrypt-auto-source/') % tag
    write(get(le_auto_dir + 'letsencrypt-auto'), temp_dir, 'letsencrypt-auto')
    write(get(le_auto_dir + 'letsencrypt-auto.sig'), temp_dir, 'letsencrypt-auto.sig')
    write(PUBLIC_KEY, temp_dir, 'public_key.pem')
    try:
        with open(devnull, 'w') as dev_null:
            check_call(['openssl', 'dgst', '-sha256', '-verify',
                        join(temp_dir, 'public_key.pem'),
                        '-signature',
                        join(temp_dir, 'letsencrypt-auto.sig'),
                        join(temp_dir, 'letsencrypt-auto')],
                       stdout=dev_null,
                       stderr=dev_null)
    except CalledProcessError as exc:
        raise ExpectedError("Couldn't verify signature of downloaded "
                            "certbot-auto.", exc)


def main():
    get = HttpsGetter().get
    flag = argv[1]
    try:
        if flag == '--latest-version':
            print(latest_stable_version(get))
        elif flag == '--le-auto-script':
            tag = argv[2]
            verified_new_le_auto(get, tag, dirname(argv[0]))
    except ExpectedError as exc:
        print(exc.args[0], exc.args[1])
        return 1
    else:
        return 0


if __name__ == '__main__':
    exit(main())
