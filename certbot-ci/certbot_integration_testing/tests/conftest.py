import tempfile
import os
import re
import subprocess
import time
import shutil

from six.moves.urllib.request import urlopen


def pytest_configure(config):
    if not os.environ.get('CERTBOT_INTEGRATION'):
        raise ValueError('Error, CERTBOT_INTEGRATION environment variable is not setted.')
    acme_ca = 'Bouler' if 'boulder' in os.environ.get('CERTBOT_INTEGRATION') else 'Pebble'

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
        url = setup_boulder(workspace)
    else:
        url = setup_pebble(workspace)

    print('=> Waiting for {0} instance to respond ...'.format(acme_ca))

    check_until_timeout(url)

    print('=> {0} instance ready.'.format(acme_ca))


def setup_boulder(workspace):
    subprocess.check_call(['git', 'clone', '--depth', '1', '--single-branch',
                           'https://github.com/letsencrypt/boulder', workspace])

    with open(os.path.join(workspace, 'docker-compose.yml'), 'r') as file:
        data = file.read()

    data = re.sub('FAKE_DNS: .*\n', 'FAKE_DNS: 10.77.77.1\n', data)
    data = re.sub('driver: none', 'driver: json-file', data)

    with open(os.path.join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    subprocess.check_call(['docker-compose', 'up', '-d', 'boulder'], cwd=workspace)

    return 'http://localhost:4000/directory'


def setup_pebble(workspace):
    raise RuntimeError('No supported yet')


def check_until_timeout(url):
    for _ in range(0, 150):
        time.sleep(1)
        try:
            if urlopen(url).getcode() == 200:
                return
        except IOError:
            pass

    raise ValueError('Error, url did not respond after 150 attempts: {0}'.format(url))
