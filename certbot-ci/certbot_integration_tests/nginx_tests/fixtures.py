import os
import subprocess
import random
import shutil
import filecmp
import contextlib

import pytest
import ssl

from certbot_integration_tests.utils import misc
from certbot_nginx.tests.nginx_config import construct_nginx_config


@pytest.fixture
def nginx_root(workspace):
    root = os.path.join(workspace, 'nginx')
    os.mkdir(root)
    return root


@pytest.fixture
def webroot(nginx_root):
    path = os.path.join(nginx_root, 'webroot')
    os.mkdir(path)
    with open(os.path.join(path, 'index.html'), 'w') as file:
        file.write('Hello World!')

    return path


@pytest.fixture
def other_port():
    return random.randint(6000,6999)


@pytest.fixture
def nginx_config(nginx_root):
    return os.path.join(nginx_root, 'nginx.conf')


@pytest.fixture
def nginx_original_config(nginx_root):
    return os.path.join(nginx_root, 'nginx-original.conf')


@pytest.fixture
def nginx_config_gen(nginx_root, nginx_config, nginx_original_config, webroot,
                     tls_sni_01_port, http_01_port, other_port):
    def func(default_server):
        config = construct_nginx_config(nginx_root, webroot, http_01_port, tls_sni_01_port, other_port, default_server)

        with open(nginx_config, 'w') as file:
            file.write(config)
        shutil.copy(nginx_config, nginx_original_config)

        return nginx_config

    return func


@pytest.fixture
def nginx(nginx_config_gen, webroot, http_01_port):
    with _nginx_setup(nginx_config_gen('default_server'), webroot, http_01_port) as configured:
        yield configured


@pytest.fixture
def nginx_no_default_srv(nginx_config_gen, webroot, http_01_port):
    with _nginx_setup(nginx_config_gen(''), webroot, http_01_port) as configured:
        yield configured


@contextlib.contextmanager
def _nginx_setup(nginx_config, webroot, http_01_port):
    assert webroot
    process = subprocess.Popen(['nginx', '-c', nginx_config, '-g', 'daemon off;'])
    try:
        assert not process.poll()
        misc.check_until_timeout('http://localhost:{0}'.format(http_01_port))
        yield True
    finally:
        process.terminate()
        process.wait()


@pytest.fixture
def certbot_test_nginx(certbot_test, nginx_root):
    def func(args):
        command = ['--authenticator', 'nginx', '--installer', 'nginx',
                   '--nginx-server-root', nginx_root]
        command.extend(args)
        return certbot_test(command)

    return func


@pytest.fixture
def assert_deployment_and_rollback(workspace, nginx_root, nginx_config, nginx_original_config,
                                   tls_sni_01_port, certbot_test_no_force_renew):
    def func(certname):
        server_cert = ssl.get_server_certificate(('localhost', tls_sni_01_port))
        with open(os.path.join(workspace, 'conf/live/{0}/cert.pem'.format(certname)), 'r') as file:
            certbot_cert = file.read()

        assert server_cert == certbot_cert

        command = ['--authenticator', 'nginx', '--installer', 'nginx',
                   '--nginx-server-root', nginx_root,
                   'rollback', '--checkpoints', '1']
        certbot_test_no_force_renew(command)

        assert filecmp.cmp(nginx_config, nginx_original_config)

    return func
