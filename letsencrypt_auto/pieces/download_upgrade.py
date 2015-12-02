from distutils.version import LooseVersion
from json import loads
from os import devnull
from os.path import dirname, join
import re
from subprocess import check_call, CalledProcessError
from sys import exit
from tempfile import mkdtemp
from urllib2 import build_opener, HTTPHandler, HTTPSHandler, HTTPError


PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
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
"""  # TODO: Replace with real one.


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


class TempDir(object):
    def __init__(self):
        self.path = mkdtemp()

    def write(self, contents, filename):
        """Write something to a named file in me."""
        with open(join(self.path, filename), 'w') as file:
            file.write(contents)


def latest_stable_version(get, package):
    """Apply a fairly safe heuristic to determine the latest stable release of
    a PyPI package."""
    metadata = loads(get('https://pypi.python.org/pypi/%s/json' % package))
    # metadata['info']['version'] actually returns the latest of any kind of
    # release release, contrary to https://wiki.python.org/moin/PyPIJSON.
    return str(max(LooseVersion(r) for r
                   in metadata['releases'].iterkeys()
                   if re.match('^[0-9.]+$', r)))


def verified_new_le_auto(get, tag, temp):
    """Return the path to a verified, up-to-date letsencrypt-auto script.

    If the download's signature does not verify or something else goes wrong,
    raise ExpectedError.

    """
    le_auto_dir = ('https://raw.githubusercontent.com/letsencrypt/letsencrypt/'
                   '%s/letsencrypt-auto/' % tag)
    temp.write(get(le_auto_dir + 'letsencrypt-auto'), 'letsencrypt-auto')
    temp.write(get(le_auto_dir + 'letsencrypt-auto.sig'), 'letsencrypt-auto.sig')
    temp.write(PUBLIC_KEY, 'public_key.pem')
    le_auto_path = join(temp.path, 'letsencrypt-auto')
    try:
        with open(devnull, 'w') as dev_null:
            check_call(['openssl', 'dgst', '-sha256', '-verify',
                        join(temp.path, 'public_key.pem'),
                        '-signature',
                        join(temp.path, 'letsencrypt-auto.sig'),
                        le_auto_path],
                       stdout=dev_null,
                       stderr=dev_null)
    except CalledProcessError as exc:
        raise ExpectedError("Couldn't verify signature of downloaded "
                            "letsencrypt-auto.", exc)
    else:  # belt & suspenders
        return le_auto_path


def main():
    get = HttpsGetter().get
    temp = TempDir()
    try:
        stable_tag = 'v' + latest_stable_version(get, 'letsencrypt')
        print dirname(verified_new_le_auto(get, stable_tag, temp))
    except ExpectedError as exc:
        print exc.args[0], exc.args[1]
        return 1
    else:
        return 0


exit(main())
