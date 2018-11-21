import ssl
import multiprocessing
import tempfile
import subprocess
import os

import pytest
from six.moves.urllib.request import urlopen
from six.moves import socketserver
from six.moves import SimpleHTTPServer


@pytest.fixture(scope='session')
def common_no_force_renew(certbot_test_no_force_renew):
    def func(args):
        command = ['--authenticator', 'standalone', '--installer', 'null']
        command.extend(args)
        certbot_test_no_force_renew(args)

    return func


@pytest.fixture(scope='session')
def common(common_no_force_renew):
    def func(args):
        command = ['--renew-by-default']
        command.extend(args)
        common_no_force_renew(args)

    return func


@pytest.fixture(scope='session', autouse=True)
def http_server(http_01_port):
    def run():
        socketserver.TCPServer(('', http_01_port),
                               SimpleHTTPServer.SimpleHTTPRequestHandler).serve_forever()

    process = multiprocessing.Process(target=run)
    process.start()

    yield

    process.terminate()


@pytest.mark.incremental
class TestSuite(object):

    def test_directory_accessibility(self, acme_url):
        context = ssl.SSLContext()
        urlopen(acme_url, context=context)

    def test_basic_commands(self, common):
        initial_count_tmpfiles = len(os.listdir(tempfile.tempdir))

        with pytest.raises(subprocess.CalledProcessError):
            common(['--csr'])
        common(['--help'])
        common(['--help', 'all'])
        common(['--version'])

        new_count_tmpfiles = len(os.listdir(tempfile.tempdir))
        assert initial_count_tmpfiles == new_count_tmpfiles
