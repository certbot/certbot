from __future__ import print_function
import tempfile
import atexit
import os
import subprocess
import shutil
import re
import contextlib

from certbot_integration_tests.utils import misc

PEBBLE_VERSION = '2018-11-02'


@contextlib.contextmanager
def setup_acme_server(acme_server):
    acme_type = 'Boulder' if 'boulder' in acme_server else 'Pebble'

    print('=> Setting up a {0} instance ...'.format(acme_type))
    tempdir = tempfile.mkdtemp()
    workspace = os.path.join(tempdir, 'src/github.com/letsencrypt/{0}'.format(acme_type.lower()))

    def cleanup():
        print('=> Tear down the {0} instance ...'.format(acme_type))

        try:
            subprocess.check_call(['docker-compose', 'down'], cwd=workspace)
        except subprocess.CalledProcessError:
            pass
        finally:
            try:
                shutil.rmtree(tempdir)
            except IOError:
                pass

        print('=> {0} instance stopped.'.format(acme_type))

    atexit.register(cleanup)

    os.makedirs(workspace)

    if acme_type == 'Boulder':
        url = _setup_boulder(workspace)
    else:
        url = _setup_pebble(workspace,
                            strict=acme_server == 'pebble-strict')

    print('=> Waiting for {0} instance to respond ...'.format(acme_type))

    misc.check_until_timeout(url)

    print('=> {0} instance ready.'.format(acme_type))
    yield


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
