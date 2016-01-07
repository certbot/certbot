"""Tests for letsencrypt-auto"""

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from contextlib import contextmanager
from functools import partial
from json import dumps
from os import environ
from os.path import abspath, dirname, join
import re
from shutil import rmtree
import socket
import ssl
from subprocess import CalledProcessError, check_output, Popen, PIPE
from tempfile import mkdtemp
from threading import Thread
from unittest import TestCase

from nose.tools import eq_, nottest, ok_

from ..build import build as build_le_auto


class RequestHandler(BaseHTTPRequestHandler):
    """An HTTPS request handler which is quiet and serves a specific folder."""

    def __init__(self, resources, *args, **kwargs):
        """
        :arg resources: A dict of resource paths pointing to content bytes

        """
        self.resources = resources
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_message(self, format, *args):
        """Don't log each request to the terminal."""

    def do_GET(self):
        """Serve a GET request."""
        content = self.send_head()
        if content is not None:
            self.wfile.write(content)

    def send_head(self):
        """Common code for GET and HEAD commands

        This sends the response code and MIME headers and returns either a
        bytestring of content or, if none is found, None.

        """
        path = self.path[1:]  # Strip leading slash.
        content = self.resources.get(path)
        if content is None:
            self.send_error(404, 'Path "%s" not found in self.resources' % path)
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            return content


def server_and_port(resources):
    """Return an unstarted HTTPS server and the port it will use."""
    # Find a port, and bind to it. I can't get the OS to close the socket
    # promptly after we shut down the server, so we typically need to try
    # a couple ports after the first test case. Setting
    # TCPServer.allow_reuse_address = True seems to have nothing to do
    # with this behavior.
    worked = False
    for port in xrange(4443, 4543):
        try:
            server = HTTPServer(('localhost', port),
                                partial(RequestHandler, resources))
        except socket.error:
            pass
        else:
            worked = True
            server.socket = ssl.wrap_socket(
                server.socket,
                certfile=join(tests_dir(), 'certs', 'localhost', 'server.pem'),
                server_side=True)
            break
    if not worked:
        raise RuntimeError("Couldn't find an unused socket for the testing HTTPS server.")
    return server, port


@contextmanager
def serving(resources):
    """Spin up a local HTTPS server, and yield its base URL.

    Use a self-signed cert generated as outlined by
    https://coolaj86.com/articles/create-your-own-certificate-authority-for-
    testing/.

    """
    server, port = server_and_port(resources)
    thread = Thread(target=server.serve_forever)
    try:
        thread.start()
        yield 'https://localhost:{port}/'.format(port=port)
    finally:
        server.shutdown()
        thread.join()


@nottest
def tests_dir():
    """Return a path to the "tests" directory."""
    return dirname(abspath(__file__))


@contextmanager
def ephemeral_dir():
    dir = mkdtemp(prefix='le-test-')
    try:
        yield dir
    finally:
        rmtree(dir)


def out_and_err(command, input=None, shell=False, env=None):
    """Run a shell command, and return stderr and stdout as string.

    If the command returns nonzero, raise CalledProcessError.

    :arg command: A list of commandline args
    :arg input: Data to pipe to stdin. Omit for none.

    Remaining args have the same meaning as for Popen.

    """
    process = Popen(command,
                    stdout=PIPE,
                    stdin=PIPE,
                    stderr=PIPE,
                    shell=shell,
                    env=env)
    out, err = process.communicate(input=input)
    status = process.poll()  # same as in check_output(), though wait() sounds better
    if status:
        raise CalledProcessError(status, command, output=out)
    return out, err


def signed(content, private_key_name='signing.key'):
    """Return the signed SHA-256 hash of ``content``, using the given key file."""
    command = ['openssl', 'dgst', '-sha256', '-sign',
               join(tests_dir(), private_key_name)]
    out, err = out_and_err(command, input=content)
    return out


def run_le_auto(venv_dir, base_url):
    """Run the prebuilt version of letsencrypt-auto, returning stdout and
    stderr strings.

    If the command returns other than 0, raise CalledProcessError.

    """
    env = environ.copy()
    d = dict(XDG_DATA_HOME=venv_dir,
             # URL to PyPI-style JSON that tell us the latest released version
             # of LE:
             LE_AUTO_JSON_URL=base_url + 'letsencrypt/json',
             # URL to dir containing letsencrypt-auto and letsencrypt-auto.sig:
             LE_AUTO_DIR_TEMPLATE=base_url + '%s/',
             # The public key corresponding to signing.key:
             LE_AUTO_PUBLIC_KEY="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMoSzLYQ7E1sdSOkwelg
tzKIh2qi3bpXuYtcfFC0XrvWig071NwIj+dZiT0OLZ2hPispEH0B7ISuuWg1ll7G
hFW0VdbxL6JdGzS2ShNWkX9hE9z+j8VqwDPOBn3ZHm03qwpYkBDwQib3KqOdYbTT
uUtJmmGcuk3a9Aq/sCT6DdfmTSdP5asdQYwIcaQreDrOosaS84DTWI3IU+UYJVgl
LsIVPBuy9IcgHidUQ96hJnoPsDCWsHwX62495QKEarauyKQrJzFes0EY95orDM47
Z5o/NDiQB11m91yNB0MmPYY9QSbnOA9j7IaaC97AwRLuwXY+/R2ablTcxurWou68
iQIDAQAB
-----END PUBLIC KEY-----""")
    env.update(d)
    return out_and_err(
        join(dirname(tests_dir()), 'letsencrypt-auto') + ' --version',
        shell=True,
        env=env)


def set_le_script_version(venv_dir, version):
    """Tell the letsencrypt script to report a certain version.

    We actually replace the script with a dummy version that knows only how to
    print its version.

    """
    with open(join(venv_dir, 'letsencrypt', 'bin', 'letsencrypt'), 'w') as script:
        script.write("#!/usr/bin/env python\n"
                     "from sys import stderr\n"
                     "stderr.write('letsencrypt %s\\n')" % version)


class AutoTests(TestCase):
    # Remove these helpers when we no longer need to support Python 2.6:
    def assertIn(self, member, container, msg=None):
        """Just like self.assertTrue(a in b), but with a nicer default message."""
        if member not in container:
            standardMsg = '%s not found in %s' % (safe_repr(member),
                                                  safe_repr(container))
            self.fail(self._formatMessage(msg, standardMsg))

    def assertNotIn(self, member, container, msg=None):
        """Just like self.assertTrue(a not in b), but with a nicer default message."""
        if member in container:
            standardMsg = '%s unexpectedly found in %s' % (safe_repr(member),
                                                        safe_repr(container))
            self.fail(self._formatMessage(msg, standardMsg))

    def test_all(self):
        """Exercise most branches of letsencrypt-auto.

        The branches:

        * An le-auto upgrade is needed.
        * An le-auto upgrade is not needed.
        * There was an out-of-date LE script installed.
        * There was a current LE script installed.
        * There was no LE script installed. (not that important)
        * Peep verification passes.
        * Peep has a hash mismatch.
        * The OpenSSL sig mismatches.

        I violate my usual rule of having small, decoupled tests, because...

        1. We shouldn't need to run a Cartesian product of the branches: the
           phases run in separate shell processes, containing state leakage
           pretty effectively. The only shared state is FS state, and it's
           limited to a temp dir, assuming (if we dare) all functions properly.
        2. One combination of branches happens to set us up nicely for testing
           the next, saving code.

        At the moment, we let bootstrapping run. We probably wanted those
        packages installed anyway for local development.

        For tests which get this far, we run merely ``letsencrypt --version``.
        The functioning of the rest of the letsencrypt script is covered by
        other test suites.

        """
        NEW_LE_AUTO = build_le_auto(version='99.9.9')
        NEW_LE_AUTO_SIG = signed(NEW_LE_AUTO)

        with ephemeral_dir() as venv_dir:
            # This serves a PyPI page with a higher version, a GitHub-alike
            # with a corresponding le-auto script, and a matching signature.
            resources = {'': '<a href="letsencrypt/">letsencrypt/</a>',
                         'letsencrypt/json': dumps({'releases': {'99.9.9': None}}),
                         'v99.9.9/letsencrypt-auto': NEW_LE_AUTO,
                         'v99.9.9/letsencrypt-auto.sig': NEW_LE_AUTO_SIG}
            with serving(resources) as base_url:
                # Test when a phase-1 upgrade is needed, there's no LE binary
                # installed, and peep verifies:
                out, err = run_le_auto(venv_dir, base_url)
                ok_(re.match(r'letsencrypt \d+\.\d+\.\d+',
                             err.strip().splitlines()[-1]))
                # Make a few assertions to test the validity of the next tests:
                self.assertIn('Upgrading letsencrypt-auto ', out)
                self.assertIn('Creating virtual environment...', out)

                # This conveniently sets us up to test the next 2 cases.

                # Test when neither phase-1 upgrade nor phase-2 upgrade is
                # needed (probably a common case):
                set_le_script_version(venv_dir, '99.9.9')
                out, err = run_le_auto(venv_dir, base_url)
                self.assertNotIn('Upgrading letsencrypt-auto ', out)
                self.assertNotIn('Creating virtual environment...', out)

                # Test when a phase-1 upgrade is not needed but a phase-2
                # upgrade is:
                set_le_script_version(venv_dir, '0.0.1')
                out, err = run_le_auto(venv_dir, base_url)
                self.assertNotIn('Upgrading letsencrypt-auto ', out)
                self.assertIn('Creating virtual environment...', out)

    # Test when peep has a hash mismatch.
    # Test when the OpenSSL sig mismatches.
