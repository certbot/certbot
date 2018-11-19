import tempfile
import os
import re
import subprocess
import time
import atexit
import shutil

from six.moves.urllib.request import urlopen


def cleanup(workspace, tempdir):
    print('=> Tear down the Boulder instance ...')

    try:
        subprocess.check_call(['docker-compose', 'down'], cwd=workspace)
    finally:
        shutil.rmtree(tempdir)

    print('=> Boulder instance stopped.')


def pytest_configure(config):
    assert config
    print('=> Setting up a Boulder instance ...')

    tempdir = tempfile.mkdtemp()
    workspace = os.path.join(tempdir, 'src/github.com/letsencrypt/boulder')

    atexit.register(cleanup, workspace, tempdir)

    os.makedirs(workspace)

    subprocess.check_call(['git', 'clone', '--depth', '1', '--single-branch',
                           'https://github.com/letsencrypt/boulder', workspace])

    with open(os.path.join(workspace, 'docker-compose.yml'), 'r') as file:
        data = file.read()

    data = re.sub('FAKE_DNS: .*\n', 'FAKE_DNS: 10.77.77.1\n', data)
    data = re.sub('driver: none', 'driver: json-file', data)

    with open(os.path.join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    subprocess.check_call(['docker-compose', 'up', '-d', 'boulder'], cwd=workspace)

    print('=> Waiting for boulder instance to respond ...')

    check_until_timeout('http://localhost:4000/directory')

    print('=> Boulder instance ready.')


def check_until_timeout(url):
    for _ in range(0, 150):
        time.sleep(1)
        try:
            if urlopen(url).getcode() == 200:
                return
        except IOError:
            pass

    raise ValueError('Error, url did not respond after 150 attempts: {0}'.format(url))
