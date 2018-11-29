import subprocess
import os

import pytest


def test_nginx_version(workspace):
    print(subprocess.check_output(['nginx' , '-v']))


testdata1 = [
    ('nginx.wtf', ['run']),
    ('nginx2.wtf', ['--preferred-challenges', 'http']),
    ('nginx3.wtf', ['--preferred-challenges', 'http']),
    ('nginx4.wtf', ['--preferred-challenges', 'http']),
]

if 'boulder' in os.environ.get('CERTBOT_INTEGRATION'):
    testdata1.insert(2, ('nginx.wtf', ['run', '--preferred-challenges', 'tls-sni']))


@pytest.mark.parametrize('certname, params', testdata1)
def test_nginx_with_default_server(certname, params, certbot_test_nginx, nginx,
                                   assert_deployment_and_rollback):
    assert nginx
    command = ['--domains', certname]
    command.extend(params)
    certbot_test_nginx(command)

    assert_deployment_and_rollback(certname)


testdata2 = [
    ('nginx5.wtf', ['--preferred-challenges', 'http']),
    ('nginx6.wtf,nginx7.wtf', ['--preferred-challenges', 'http']),
]


@pytest.mark.parametrize('certname, params', testdata2)
def test_nginx_without_default_server(certname, params, certbot_test_nginx, nginx_no_default_srv,
                                      assert_deployment_and_rollback):
    assert nginx_no_default_srv
    command = ['--domains', certname]
    command.extend(params)
    certbot_test_nginx(command)

    assert_deployment_and_rollback(certname.split(',')[0])
