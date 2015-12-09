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
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnwHkSuCSy3gIHawaCiIe
4ilJ5kfEmSoiu50uiimBhTESq1JG2gVqXVXFxxVgobGhahSF+/iRVp3imrTtGp1B
2heoHbELnPTTZ8E36WHKf4gkLEo0y0XgOP3oBJ9IM5q8J68x0U3Q3c+kTxd/sgww
s5NVwpjw4aAZhgDPe5u+rvthUYOD1whYUANgYvooCpV4httNv5wuDjo7SG2V797T
QTE8aG3AOhWzdsLm6E6Tl2o/dR6XKJi/RMiXIk53SzArimtAJXe/1GyADe1AgIGE
33Ja3hU3uu9lvnnkowy1VI0qvAav/mu/APahcWVYkBAvSVAhH3zGNAGZUnP2zfcP
rH7OPw/WrxLVGlX4trLnvQr1wzX7aiM2jdikcMiaExrP0JfQXPu00y3c+hjOC5S0
+E5P+e+8pqz5iC5mmvEqy2aQJ6pV7dSpYX3mcDs8pCYaVXXtCPXS1noWirCcqCMK
EHGGdJCTXXLHaWUaGQ9Gx1An1gU7Ljkkji2Al65ZwYhkFowsLfuniYKuAywRrCNu
q958HnzFpZiQZAqZYtOHaiQiaHPs/36ZN0HuOEy0zM9FEHbp4V/DEn4pNCfAmRY5
3v+3nIBhgiLdlM7cV9559aDNeutF25n1Uz2kvuSVSS94qTEmlteCPZGBQb9Rr2wn
I2OU8tPRzqKdQ6AwS9wvqscCAwEAAQ==
-----END PUBLIC KEY-----
""")  # TODO: Replace with real one.


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
                    'https://pypi.python.org/pypi/letsencrypt/json')))
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
        'LE_AUTO_DOWNLOAD_TEMPLATE',
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


exit(main())
