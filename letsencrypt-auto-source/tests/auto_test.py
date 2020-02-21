"""Tests for letsencrypt-auto"""

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from contextlib import contextmanager
from functools import partial
from json import dumps
from os import chmod, environ, makedirs, stat
from os.path import abspath, dirname, exists, join
import re
from shutil import copy, rmtree
import socket
import ssl
from stat import S_IMODE, S_IRUSR, S_IWUSR, S_IXUSR, S_IWGRP, S_IWOTH
from subprocess import CalledProcessError, Popen, PIPE
import sys
from tempfile import mkdtemp
from threading import Thread
from unittest import TestCase

from pytest import mark
from six.moves import xrange  # pylint: disable=redefined-builtin


@mark.skip
def tests_dir():
    """Return a path to the "tests" directory."""
    return dirname(abspath(__file__))


def copy_stable(src, dst):
    """
    Copy letsencrypt-auto, and replace its current version to its equivalent stable one.
    This is needed to test correctly the self-upgrade functionality.
    """
    copy(src, dst)
    with open(dst, 'r') as file:
        filedata = file.read()
    filedata = re.sub(r'LE_AUTO_VERSION="(.*)\.dev0"', r'LE_AUTO_VERSION="\1"', filedata)
    with open(dst, 'w') as file:
        file.write(filedata)


sys.path.insert(0, dirname(tests_dir()))
from build import build as build_le_auto


BOOTSTRAP_FILENAME = 'certbot-auto-bootstrap-version.txt'
"""Name of the file where certbot-auto saves its bootstrap version."""


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


LE_AUTO_PATH = join(dirname(tests_dir()), 'letsencrypt-auto')


@contextmanager
def temp_paths():
    """Creates and deletes paths for letsencrypt-auto and its venv."""
    dir = mkdtemp(prefix='le-test-')
    try:
        yield join(dir, 'letsencrypt-auto'), join(dir, 'venv')
    finally:
        rmtree(dir, ignore_errors=True)


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
        error = CalledProcessError(status, command)
        error.output = out
        print('stdout output was:')
        print(out)
        print('stderr output was:')
        print(err)
        raise error
    return out, err


def signed(content, private_key_name='signing.key'):
    """Return the signed SHA-256 hash of ``content``, using the given key file."""
    command = ['openssl', 'dgst', '-sha256', '-sign',
               join(tests_dir(), private_key_name)]
    out, err = out_and_err(command, input=content)
    return out


def install_le_auto(contents, install_path):
    """Install some given source code as the letsencrypt-auto script at the
    root level of a virtualenv.

    :arg contents: The contents of the built letsencrypt-auto script
    :arg install_path: The path where to install the script

    """
    with open(install_path, 'w') as le_auto:
        le_auto.write(contents)
    chmod(install_path, S_IRUSR | S_IXUSR)


def run_le_auto(le_auto_path, venv_dir, base_url=None, le_auto_args_str='--version', **kwargs):
    """Run the prebuilt version of letsencrypt-auto, returning stdout and
    stderr strings.

    If the command returns other than 0, raise CalledProcessError.

    """
    env = environ.copy()
    d = dict(VENV_PATH=venv_dir,
             NO_CERT_VERIFY='1',
             **kwargs)

    if base_url is not None:
        # URL to PyPI-style JSON that tell us the latest released version
        # of LE:
        d['LE_AUTO_JSON_URL'] = base_url + 'certbot/json'
        # URL to dir containing letsencrypt-auto and letsencrypt-auto.sig:
        d['LE_AUTO_DIR_TEMPLATE'] = base_url + '%s/'
        # The public key corresponding to signing.key:
        d['LE_AUTO_PUBLIC_KEY'] = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMoSzLYQ7E1sdSOkwelg
tzKIh2qi3bpXuYtcfFC0XrvWig071NwIj+dZiT0OLZ2hPispEH0B7ISuuWg1ll7G
hFW0VdbxL6JdGzS2ShNWkX9hE9z+j8VqwDPOBn3ZHm03qwpYkBDwQib3KqOdYbTT
uUtJmmGcuk3a9Aq/sCT6DdfmTSdP5asdQYwIcaQreDrOosaS84DTWI3IU+UYJVgl
LsIVPBuy9IcgHidUQ96hJnoPsDCWsHwX62495QKEarauyKQrJzFes0EY95orDM47
Z5o/NDiQB11m91yNB0MmPYY9QSbnOA9j7IaaC97AwRLuwXY+/R2ablTcxurWou68
iQIDAQAB
-----END PUBLIC KEY-----"""

    env.update(d)

    return out_and_err(
        le_auto_path + ' ' + le_auto_args_str,
        shell=True,
        env=env)


def set_le_script_version(venv_dir, version):
    """Tell the letsencrypt script to report a certain version.

    We actually replace the script with a dummy version that knows only how to
    print its version.

    """
    letsencrypt_path = join(venv_dir, 'bin', 'letsencrypt')
    with open(letsencrypt_path, 'w') as script:
        script.write("#!/usr/bin/env python\n"
                     "from sys import stderr\n"
                     "stderr.write('letsencrypt %s\\n')" % version)
    chmod(letsencrypt_path, S_IRUSR | S_IXUSR)


def sudo_chmod(path, mode):
    """Runs `sudo chmod mode path`."""
    mode = oct(mode).replace('o', '')
    out_and_err(['sudo', 'chmod', mode, path])


class AutoTests(TestCase):
    """Test the major branch points of letsencrypt-auto:

    * An le-auto upgrade is needed.
    * An le-auto upgrade is not needed.
    * There was an out-of-date LE script installed.
    * There was a current LE script installed.
    * There was no LE script installed (less important).
    * Pip hash-verification passes.
    * Pip has a hash mismatch.
    * The OpenSSL sig matches.
    * The OpenSSL sig mismatches.

    For tests which get to the end, we run merely ``letsencrypt --version``.
    The functioning of the rest of the certbot script is covered by other
    test suites.

    """
    NEW_LE_AUTO = build_le_auto(
            version='99.9.9',
            requirements='letsencrypt==99.9.9 --hash=sha256:1cc14d61ab424cdee446f51e50f1123f8482ec740587fe78626c933bba2873a0')
    NEW_LE_AUTO_SIG = signed(NEW_LE_AUTO)

    def test_successes(self):
        """Exercise most branches of letsencrypt-auto.

        They just happen to be the branches in which everything goes well.

        I violate my usual rule of having small, decoupled tests, because...

        1. We shouldn't need to run a Cartesian product of the branches: the
           phases run in separate shell processes, containing state leakage
           pretty effectively. The only shared state is FS state, and it's
           limited to a temp dir, assuming (if we dare) all functions properly.
        2. One combination of branches happens to set us up nicely for testing
           the next, saving code.

        """
        with temp_paths() as (le_auto_path, venv_dir):
            # This serves a PyPI page with a higher version, a GitHub-alike
            # with a corresponding le-auto script, and a matching signature.
            resources = {'certbot/json': dumps({'releases': {'99.9.9': None}}),
                         'v99.9.9/letsencrypt-auto': self.NEW_LE_AUTO,
                         'v99.9.9/letsencrypt-auto.sig': self.NEW_LE_AUTO_SIG}
            with serving(resources) as base_url:
                run_letsencrypt_auto = partial(
                        run_le_auto,
                        le_auto_path,
                        venv_dir,
                        base_url,
                        PIP_FIND_LINKS=join(tests_dir(),
                                            'fake-letsencrypt',
                                            'dist'))

                # Test when a phase-1 upgrade is needed, there's no LE binary
                # installed, and pip hashes verify:
                install_le_auto(build_le_auto(version='50.0.0'), le_auto_path)
                out, err = run_letsencrypt_auto()
                self.assertTrue(re.match(r'letsencrypt \d+\.\d+\.\d+',
                                err.strip().splitlines()[-1]))
                # Make a few assertions to test the validity of the next tests:
                self.assertTrue('Upgrading certbot-auto ' in out)
                self.assertTrue('Creating virtual environment...' in out)

                # Now we have le-auto 99.9.9  and LE 99.9.9 installed. This
                # conveniently sets us up to test the next 2 cases.

                # Test when neither phase-1 upgrade nor phase-2 upgrade is
                # needed (probably a common case):
                out, err = run_letsencrypt_auto()
                self.assertFalse('Upgrading certbot-auto ' in out)
                self.assertFalse('Creating virtual environment...' in out)

    def test_phase2_upgrade(self):
        """Test a phase-2 upgrade without a phase-1 upgrade."""
        resources = {'certbot/json': dumps({'releases': {'99.9.9': None}}),
                     'v99.9.9/letsencrypt-auto': self.NEW_LE_AUTO,
                     'v99.9.9/letsencrypt-auto.sig': self.NEW_LE_AUTO_SIG}
        with serving(resources) as base_url:
            pip_find_links=join(tests_dir(), 'fake-letsencrypt', 'dist')
            with temp_paths() as (le_auto_path, venv_dir):
                install_le_auto(self.NEW_LE_AUTO, le_auto_path)

                # Create venv saving the correct bootstrap script version
                out, err = run_le_auto(le_auto_path, venv_dir, base_url,
                                       PIP_FIND_LINKS=pip_find_links)
                self.assertFalse('Upgrading certbot-auto ' in out)
                self.assertTrue('Creating virtual environment...' in out)
                with open(join(venv_dir, BOOTSTRAP_FILENAME)) as f:
                    bootstrap_version = f.read()

            # Create a new venv with an old letsencrypt version
            with temp_paths() as (le_auto_path, venv_dir):
                venv_bin = join(venv_dir, 'bin')
                makedirs(venv_bin)
                set_le_script_version(venv_dir, '0.0.1')
                with open(join(venv_dir, BOOTSTRAP_FILENAME), 'w') as f:
                    f.write(bootstrap_version)

                install_le_auto(self.NEW_LE_AUTO, le_auto_path)
                out, err = run_le_auto(le_auto_path, venv_dir, base_url,
                                       PIP_FIND_LINKS=pip_find_links)

                self.assertFalse('Upgrading certbot-auto ' in out)
                self.assertTrue('Creating virtual environment...' in out)

    def test_openssl_failure(self):
        """Make sure we stop if the openssl signature check fails."""
        with temp_paths() as (le_auto_path, venv_dir):
            # Serve an unrelated hash signed with the good key (easier than
            # making a bad key, and a mismatch is a mismatch):
            resources = {'': '<a href="certbot/">certbot/</a>',
                         'certbot/json': dumps({'releases': {'99.9.9': None}}),
                         'v99.9.9/letsencrypt-auto': build_le_auto(version='99.9.9'),
                         'v99.9.9/letsencrypt-auto.sig': signed('something else')}
            with serving(resources) as base_url:
                copy_stable(LE_AUTO_PATH, le_auto_path)
                try:
                    out, err = run_le_auto(le_auto_path, venv_dir, base_url)
                except CalledProcessError as exc:
                    self.assertEqual(exc.returncode, 1)
                    self.assertTrue("Couldn't verify signature of downloaded "
                                    "certbot-auto." in exc.output)
                else:
                    print(out)
                    self.fail('Signature check on certbot-auto erroneously passed.')

    def test_pip_failure(self):
        """Make sure pip stops us if there is a hash mismatch."""
        with temp_paths() as (le_auto_path, venv_dir):
            resources = {'': '<a href="certbot/">certbot/</a>',
                         'certbot/json': dumps({'releases': {'99.9.9': None}})}
            with serving(resources) as base_url:
                # Build a le-auto script embedding a bad requirements file:
                install_le_auto(
                    build_le_auto(
                        version='99.9.9',
                        requirements='configobj==5.0.6 --hash=sha256:badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb'),
                    le_auto_path)
                try:
                    out, err = run_le_auto(le_auto_path, venv_dir, base_url)
                except CalledProcessError as exc:
                    self.assertEqual(exc.returncode, 1)
                    self.assertTrue("THESE PACKAGES DO NOT MATCH THE HASHES "
                                    "FROM THE REQUIREMENTS FILE" in exc.output)
                    self.assertFalse(
                        exists(venv_dir),
                        msg="The virtualenv was left around, even though "
                            "installation didn't succeed. We shouldn't do "
                            "this, as it foils our detection of whether we "
                            "need to recreate the virtualenv, which hinges "
                            "on the presence of $VENV_BIN/letsencrypt.")
                else:
                    self.fail("Pip didn't detect a bad hash and stop the "
                              "installation.")

    def test_permissions_warnings(self):
        """Make sure letsencrypt-auto properly warns about permissions problems."""
        # This test assumes that only the parent of the directory containing
        # letsencrypt-auto (usually /tmp) may have permissions letsencrypt-auto
        # considers insecure.
        with temp_paths() as (le_auto_path, venv_dir):
            le_auto_path = abspath(le_auto_path)
            le_auto_dir = dirname(le_auto_path)
            le_auto_dir_parent = dirname(le_auto_dir)
            install_le_auto(self.NEW_LE_AUTO, le_auto_path)

            run_letsencrypt_auto = partial(
                run_le_auto, le_auto_path, venv_dir,
                le_auto_args_str='--install-only --no-self-upgrade',
                PIP_FIND_LINKS=join(tests_dir(), 'fake-letsencrypt', 'dist'))
            # Run letsencrypt-auto once with current permissions to avoid
            # potential problems when the script tries to write to temporary
            # directories.
            run_letsencrypt_auto()

            le_auto_dir_mode = stat(le_auto_dir).st_mode
            le_auto_dir_parent_mode = S_IMODE(stat(le_auto_dir_parent).st_mode)
            try:
                # Make letsencrypt-auto happy with the current permissions
                chmod(le_auto_dir, S_IRUSR | S_IXUSR)
                sudo_chmod(le_auto_dir_parent, 0o755)

                self._test_permissions_warnings_about_path(le_auto_path, run_letsencrypt_auto)
                self._test_permissions_warnings_about_path(le_auto_dir, run_letsencrypt_auto)
            finally:
                chmod(le_auto_dir, le_auto_dir_mode)
                sudo_chmod(le_auto_dir_parent, le_auto_dir_parent_mode)

    def _test_permissions_warnings_about_path(self, path, run_le_auto_func):
        # Test that there are no problems with the current permissions
        out, _ = run_le_auto_func()
        self.assertFalse('insecure permissions' in out)

        stat_result = stat(path)
        original_mode = stat_result.st_mode

        # Test world permissions
        chmod(path, original_mode | S_IWOTH)
        out, _ = run_le_auto_func()
        self.assertTrue('insecure permissions' in out)

        # Test group permissions
        if stat_result.st_gid >= 1000:
            chmod(path, original_mode | S_IWGRP)
            out, _ = run_le_auto_func()
            self.assertTrue('insecure permissions' in out)

        # Test owner permissions
        if stat_result.st_uid >= 1000:
            chmod(path, original_mode | S_IWUSR)
            out, _ = run_le_auto_func()
            self.assertTrue('insecure permissions' in out)

        # Test that permissions were properly restored
        chmod(path, original_mode)
        out, _ = run_le_auto_func()
        self.assertFalse('insecure permissions' in out)

    def test_disabled_permissions_warnings(self):
        """Make sure that letsencrypt-auto permissions warnings can be disabled."""
        with temp_paths() as (le_auto_path, venv_dir):
            le_auto_path = abspath(le_auto_path)
            install_le_auto(self.NEW_LE_AUTO, le_auto_path)

            le_auto_args_str='--install-only --no-self-upgrade'
            pip_links=join(tests_dir(), 'fake-letsencrypt', 'dist')
            out, _ = run_le_auto(le_auto_path, venv_dir,
                                 le_auto_args_str=le_auto_args_str,
                                 PIP_FIND_LINKS=pip_links)
            self.assertTrue('insecure permissions' in out)

            # Test that warnings are disabled when the script isn't run as
            # root.
            out, _ = run_le_auto(le_auto_path, venv_dir,
                                 le_auto_args_str=le_auto_args_str,
                                 LE_AUTO_SUDO='',
                                 PIP_FIND_LINKS=pip_links)
            self.assertFalse('insecure permissions' in out)

            # Test that --no-permissions-check disables warnings.
            le_auto_args_str += ' --no-permissions-check'
            out, _ = run_le_auto(
                le_auto_path, venv_dir,
                le_auto_args_str=le_auto_args_str,
                PIP_FIND_LINKS=pip_links)
            self.assertFalse('insecure permissions' in out)
