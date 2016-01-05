"""Do downloading and JSON parsing without additional dependencies. ::

    # Print latest released version of LE to stdout:
    python fetch.py --latest-version
    
    # Download letsencrypt-auto script from git tag v1.2.3 into the folder I'm
    # in, and make sure its signature verifies:
    python fetch.py --le-auto-script v1.2.3

On failure, return non-zero.

"""
from distutils.version import LooseVersion
from json import loads
from os import devnull, environ
from os.path import dirname, join
import re
from subprocess import check_call, CalledProcessError
from sys import argv, exit
from urllib2 import build_opener, HTTPHandler, HTTPSHandler, HTTPError


PUBLIC_KEY = environ.get('LE_AUTO_PUBLIC_KEY', """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvWrG8oyI2FlCWEEEo1+Q
+VmDgUdMKGWlThHm5oM6XODDpllY8gUGWoYn//jCUMQuQmDTtvPz1V6s5uoESnG3
PUjEj539Dt3bQmfm5eRN17DXb3FR4l4eKkYE/bDHvGvWsI3B1b2ek0mK88XEoUxg
hx7tre19X8Q5N4ssii1+HW51e6NHO6S2fa7mko85RcF0ZHSvOVwMELbVYg+GVlmz
5K39QNqcBr2RcWmTR9XpRkV6F7DPm4XsSKd51McHiatG4vCzMpMw5R96aY4Y/wg+
lLMOJYYAQEv7ii8exClMCTUiTzVevI0mSXyHxRcILFNRYrgc5OBNtf1w2ZjcHKAr
9QIDAQAB
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
                    'https://raw.githubusercontent.com/letsencrypt/letsencrypt/letsencrypt-auto-release-testing/pypi.json')))
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
        'https://raw.githubusercontent.com/letsencrypt/letsencrypt/%s/'
        'letsencrypt-auto/') % tag
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
                            "letsencrypt-auto.", exc)


def main():
    get = HttpsGetter().get
    flag = argv[1]
    try:
        if flag == '--latest-version':
            print latest_stable_version(get)
        elif flag == '--le-auto-script':
            tag = argv[2]
            verified_new_le_auto(get, tag, dirname(argv[0]))
    except ExpectedError as exc:
        print exc.args[0], exc.args[1]
        return 1
    else:
        return 0


if __name__ == '__main__':
    exit(main())
