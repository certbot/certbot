import tempfile
import re
import shutil
import subprocess
import os
import pytest

from certbot_integration_testing.utils import misc


PEBBLE_VERSION = '2018-11-02'

pytest_plugins = [
    'certbot_integration_testing.utils.fixtures_session',
    'certbot_integration_testing.utils.fixtures_module',
    'certbot_integration_testing.utils.fixtures_function'
]


def pytest_configure(config):
    if not os.environ.get('CERTBOT_INTEGRATION'):
        raise ValueError('Error, CERTBOT_INTEGRATION environment variable is not setted.')
    acme_ca = 'Boulder' if 'boulder' in os.environ.get('CERTBOT_INTEGRATION') else 'Pebble'

    print('=> Setting up a {0} instance ...'.format(acme_ca))
    tempdir = tempfile.mkdtemp()
    workspace = os.path.join(tempdir, 'src/github.com/letsencrypt/{0}'.format(acme_ca.lower()))

    def cleanup():
        print('=> Tear down the {0} instance ...'.format(acme_ca))

        try:
            subprocess.check_call(['docker-compose', 'down'], cwd=workspace)
        except subprocess.CalledProcessError:
            pass
        finally:
            try:
                shutil.rmtree(tempdir)
            except IOError:
                pass

        print('=> {0} instance stopped.'.format(acme_ca))

    config.add_cleanup(cleanup)

    os.makedirs(workspace)

    if acme_ca == 'Boulder':
        url = _setup_boulder(workspace)
    else:
        url = _setup_pebble(workspace,
                            strict=os.environ.get('CERTBOT_INTEGRATION') == 'pebble-strict')

    print('=> Waiting for {0} instance to respond ...'.format(acme_ca))

    misc.check_until_timeout(url)

    print('=> {0} instance ready.'.format(acme_ca))


def pytest_runtest_makereport(item, call):
    if 'incremental' in item.keywords:
        if call.excinfo is not None and call.excinfo.typename != 'SkipTest':
            parent = item.parent
            parent._previousfailed = item


def pytest_runtest_setup(item):
    if 'incremental' in item.keywords:
        previousfailed = getattr(item.parent, '_previousfailed', None)
        if previousfailed is not None:
            pytest.xfail('Previous test failed in incremental test suite: {0}'
                         .format(previousfailed.name))


def _setup_boulder(workspace):
    subprocess.check_call(['git', 'clone', '--depth', '1', '--single-branch',
                           'https://github.com/letsencrypt/boulder', workspace])

    with open(os.path.join(workspace, 'docker-compose.yml'), 'r') as file:
        data = file.read()

    data = re.sub('FAKE_DNS: .*\n', 'FAKE_DNS: 10.77.77.1\n', data)

    with open(os.path.join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    subprocess.check_call(['docker-compose', 'up', '-d', 'boulder'], cwd=workspace)

    return 'http://localhost:4000/directory'


def _setup_pebble(workspace, strict=False):
    data = '''\
version: '3'
services:
 pebble:
  image: letsencrypt/pebble:{0}
  command: pebble -dnsserver 10.77.77.1:53 {1}
  ports:
    - 14000:14000
  environment:
    - PEBBLE_VA_NOSLEEP=1
'''.format(PEBBLE_VERSION, '-strict' if strict else '')

    print(data)

    with open(os.path.join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    subprocess.check_call(['docker-compose', 'up', '-d', 'pebble'], cwd=workspace)

    return 'https://localhost:14000/dir'

