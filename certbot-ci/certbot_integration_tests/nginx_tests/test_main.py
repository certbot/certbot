import subprocess

import pytest


def test_nginx_version():
    print(subprocess.check_output(['nginx', '-v']))


testdata1 = [
    ('nginx.{0}.wtf', ['run']),
    ('nginx2.{0}.wtf', ['--preferred-challenges', 'http']),
    ('nginx3.{0}.wtf', ['--preferred-challenges', 'http']),
    ('nginx4.{0}.wtf', ['--preferred-challenges', 'http']),
]


@pytest.mark.parametrize('certname_pattern, params', testdata1)
def test_nginx_with_default_server(certname_pattern, params, context):
    with context.nginx_server('default_server'):
        certname = certname_pattern.format(context.worker_id)
        command = ['--domains', certname]
        command.extend(params)
        context.certbot_test_nginx(command)

        context.assert_deployment_and_rollback(certname)


testdata2 = [
    ('nginx5.{0}.wtf', ['--preferred-challenges', 'http']),
    ('nginx6.{0}.wtf,nginx7.{0}.wtf', ['--preferred-challenges', 'http']),
]


@pytest.mark.parametrize('certname_pattern, params', testdata2)
def test_nginx_without_default_server(certname_pattern, params, context):
    with context.nginx_server('default_server'):
        certname = certname_pattern.format(context.worker_id)
        command = ['--domains', certname]
        command.extend(params)
        context.certbot_test_nginx(command)

        context.assert_deployment_and_rollback(certname.split(',')[0])
