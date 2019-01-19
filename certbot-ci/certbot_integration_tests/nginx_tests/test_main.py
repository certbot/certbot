import subprocess
import os

import pytest


def test_nginx_version(workspace):
    print(subprocess.check_output(['nginx', '-v']))


testdata1 = [
    ('nginx.{0}.wtf', ['run']),
    ('nginx2.{0}.wtf', ['--preferred-challenges', 'http']),
    ('nginx3.{0}.wtf', ['--preferred-challenges', 'http']),
    ('nginx4.{0}.wtf', ['--preferred-challenges', 'http']),
]


@pytest.mark.parametrize('certname_pattern, params', testdata1)
def test_nginx_with_default_server(certname_pattern, params, certbot_test_nginx, worker_id,
                                   nginx, assert_deployment_and_rollback):
    assert nginx
    certname = certname_pattern.format(worker_id)
    command = ['--domains', certname]
    command.extend(params)
    certbot_test_nginx(command)

    assert_deployment_and_rollback(certname)


testdata2 = [
    ('nginx5.{0}.wtf', ['--preferred-challenges', 'http']),
    ('nginx6.{0}.wtf,nginx7.{0}.wtf', ['--preferred-challenges', 'http']),
]


@pytest.mark.parametrize('certname_pattern, params', testdata2)
def test_nginx_without_default_server(certname_pattern, params, certbot_test_nginx, worker_id,
                                      nginx_no_default_srv, assert_deployment_and_rollback):
    assert nginx_no_default_srv
    certname = certname_pattern.format(worker_id)
    command = ['--domains', certname]
    command.extend(params)
    certbot_test_nginx(command)

    assert_deployment_and_rollback(certname.split(',')[0])
