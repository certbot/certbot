#!/bin/sh
set -e  # Work even if somebody does "sh thisscript.sh".

# If not --_skip-to-install:
    # Bootstrap
    # TODO: Inline the bootstrap scripts by putting each one into its own function (so they don't leak scope).

PYTHON=python
SUDO=sudo

if [ "$1" != "--_skip-to-install" ]; then
    echo "Upgrading letsencrypt-auto..."
    # Now we drop into python so we don't have to install even more
    # dependencies (curl, etc.), for better flow control, and for the option of
    # future Windows compatibility.
    #
    # The following Python script prints a path to a temp dir containing a new
    # copy of letsencrypt-auto or returns non-zero. There is no $ interpolation
    # due to quotes on heredoc delimiters.
    set +e
    TEMP_DIR=`$PYTHON - <<"UNLIKELY_EOF"

from distutils.version import LooseVersion
from json import loads
from os import devnull
from os.path import join
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
    root = ('https://raw.githubusercontent.com/letsencrypt/letsencrypt/%s/' %
            tag)
    temp.write(get(root + 'letsencrypt-auto'), 'letsencrypt-auto')
    temp.write(get(root + 'letsencrypt-auto.sig'), 'letsencrypt-auto.sig')
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
"UNLIKELY_EOF"`
    DOWNLOAD_STATUS=$?
    set -e
    if [ "$DOWNLOAD_STATUS" = 0 ]; then
        # Install new copy of letsencrypt-auto. This preserves permissions and
        # ownership from the old copy.
        # TODO: Deal with quotes in pathnames.
        # TODO: Don't bother upgrading if we're already up to date.
        echo "  " $SUDO cp "$TEMP_DIR/letsencrypt-auto" "$0"
        $SUDO cp "$TEMP_DIR/letsencrypt-auto" "$0"
        # TODO: Clean up temp dir safely, even if it has quotes in its path.
        "$0" --_skip-to-install "$TEMP_DIR" "$@"
    else
        # Report error:
        echo $TEMP_DIR
        exit 1
    fi
else  # --_skip-to-install was passed.
    # Install Python dependencies with peep.
    echo skipping!
fi
