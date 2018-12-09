import os
import ssl
import time
import contextlib

from six.moves.urllib.request import urlopen


def check_until_timeout(url):
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)

    for _ in range(0, 150):
        time.sleep(1)
        try:
            if urlopen(url, context=context).getcode() == 200:
                return
        except IOError:
            pass

    raise ValueError('Error, url did not respond after 150 attempts: {0}'.format(url))


@contextlib.contextmanager
def execute_in_given_cwd(cwd):
    current_cwd = os.getcwd()
    try:
        os.chdir(cwd)
        yield
    finally:
        os.chdir(current_cwd)
