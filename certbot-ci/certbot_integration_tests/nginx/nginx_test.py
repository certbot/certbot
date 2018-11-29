import subprocess
import os

import pytest


def test_nginx_version(workspace):
    print(subprocess.check_output(['nginx' , '-v']))


testdata = [
    ('nginx.wtf', ['run']),
    ('nginx2.wtf', ['--preferred-challenges', 'http']),
    ('nginx3.wtf', ['--preferred-challenges', 'http']),
    ('nginx4.wtf', ['--preferred-challenges', 'http']),
]

if 'boulder' in os.environ.get('CERTBOT_INTEGRATION'):
    testdata.insert(2, ('nginx.wtf', ['run', '--preferred-challenges', 'tls-sni']))


@pytest.mark.parametrize('certname, params', testdata)
def test_nginx(certname, params, certbot_test_no_force_renew, nginx_root,
               assert_deployment_and_rollback):
    command = ['--authenticator', 'nginx', '--installer', 'nginx',
               '--nginx-server-root', nginx_root, '--domains', certname]
    command.extend(params)
    certbot_test_no_force_renew(command)
    assert_deployment_and_rollback(certname)
