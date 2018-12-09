from __future__ import print_function
import tempfile
import atexit
import os
import subprocess
import re
import contextlib
import multiprocessing
import shutil
import sys
from os.path import join, exists

import requests

from certbot_integration_tests.utils import misc

BOULDER_VERSION = '2018-11-19'
TRAVIS_GO_VERSION = '1.11.2'


@contextlib.contextmanager
def setup_acme_server(acme_config, nodes, repositories_path):
    acme_type = acme_config['type']
    acme_xdist = {'master': {}}

    with _prepare_repository(repositories_path, acme_type) as repo_path:
        pool = multiprocessing.Pool(processes=len(nodes))
        expected_results = [_setup_one_node(index, node, acme_config, pool, repo_path)
                            for (index, node) in enumerate(nodes)]
        results = [result.get() for result in expected_results]

        if False in results:
            raise ValueError('One instance of {0} did not start correctly.'.format(acme_type))

        for (index, node) in enumerate(nodes):
            acme_xdist[node] = results[index]

        yield acme_xdist


@contextlib.contextmanager
def _prepare_repository(repositories_path, acme_type):
    print('=> Preparing GIT repositories...')
    repo_path = join(repositories_path, acme_type)

    try:
        if not exists(repo_path):
            launch_command(['git', 'clone', 'https://github.com/letsencrypt/{0}'.format(acme_type),
                            '--single-branch', '--depth=1', repo_path])

        launch_command(['git', 'clean', '-fd'], cwd=repo_path)
        launch_command(['git', 'checkout', '-B', 'master', 'origin/master'], cwd=repo_path)
        launch_command(['git', 'pull'], cwd=repo_path)
        print('=> GIT repositories ready.')
        yield repo_path
    except (OSError, subprocess.CalledProcessError):
        shutil.rmtree(repositories_path)


def _setup_one_node(index, node, acme_config, pool, repo_path):
    acme_type = acme_config['type']
    print('=> Setting up a {0} instance ({1})...'.format(acme_type, node))
    workspace = tempfile.mkdtemp()

    def cleanup():
        print('=> Tear down the {0} instance ({1})...'.format(acme_type, node))

        try:
            if os.path.isfile(join(workspace, 'docker-compose.yml')):
                launch_command(['docker-compose', '-p', node, 'down'],
                               cwd=workspace)
        except subprocess.CalledProcessError:
            pass
        finally:
            try:
                shutil.rmtree(workspace)
            except IOError:
                pass

        print('=> {0} instance stopped ({1}).'.format(acme_type, node))

    atexit.register(cleanup)

    return pool.apply_async(_async_work, (workspace, index, acme_config, node, repo_path))


def _async_work(workspace, index, acme_config, node, repo_path):
    acme_type = acme_config['type']
    params = {
        'node': node,
        'https_01_port': 5001 + 10 * index,
        'http_01_port': 5002 + 10 * index,
        'directory_v1_port': 5003 + 10 * index,
        'directory_v2_port': 5004 + 10 * index,
        'challsrvport_mgt_port': 5005 + 10 * index,
        'bluenet_network': '10.77.{0}'.format(index),
        'rednet_network': '10.88.{0}'.format(index),
    }

    ignore = shutil.ignore_patterns('.git')
    shutil.copytree(repo_path, join(workspace, acme_type), ignore=ignore)

    if acme_type == 'boulder':
        directory_url = _setup_boulder(workspace, params, acme_v2=acme_config['option'] == 'v2')
    else:
        directory_url = _setup_pebble(workspace, params, strict=acme_config['option'] == 'strict')

    xdist = {
        'directory_url': directory_url,
        'https_01_port': params['https_01_port'],
        'http_01_port': params['http_01_port'],
        'challsrvtest_mgt_port': params['challsrvport_mgt_port']
    }

    print('configured')

    launch_command(['docker-compose', '--project-name', params['node'],
                    'up', '--force-recreate', '-d', acme_config['type']], cwd=workspace)

    print('=> Waiting for {0} instance to respond ({1})...'.format(acme_type, node))

    print(directory_url)

    # try:
    #     misc.check_until_timeout(directory_url)
    # except ValueError:
    #     print('check error')
    #     return False
    # except:
    #     print('error !!!!')
    #     raise

    if acme_type == 'pebble':
        response = requests.post('http://localhost:{0}/set-default-ipv4'
                                 .format(params['challsrvport_mgt_port']),
                                 '{{"ip":"{0}.1"}}'.format(params['bluenet_network']))
        response.raise_for_status()

    print('=> {0} instance ready ({1}).'.format(acme_type, node))

    return xdist


def _setup_boulder(workspace, params, acme_v2):
    data = '''
version: '3'
services:
    boulder:
        # To minimize fetching this should be the same version used below
        image: letsencrypt/boulder-tools-go{travis_go_version}:{boulder_version}
        environment:
            FAKE_DNS: 10.77.77.1
            PKCS11_PROXY_SOCKET: tcp://boulder-hsm:5657
            BOULDER_CONFIG_DIR: test/config
        volumes:
          - ./boulder:/go/src/github.com/letsencrypt/boulder
          - ./boulder/.gocache:/root/.cache/go-build
        networks:
          bluenet_{node}:
            ipv4_address: 10.77.77.77
            aliases:
              - sa1.boulder
              - ca1.boulder
              - ra1.boulder
              - va1.boulder
              - publisher1.boulder
              - ocsp-updater.boulder
              - admin-revoker.boulder
          rednet_{node}:
            ipv4_address: 10.88.88.88
            aliases:
              - sa2.boulder
              - ca2.boulder
              - ra2.boulder
              - va2.boulder
              - publisher2.boulder
        # Use sd-test-srv as a backup to Docker's embedded DNS server
        # (https://docs.docker.com/config/containers/container-networking/#dns-services).
        # If there's a name Docker's DNS server doesn't know about, it will
        # forward the query to this IP (running sd-test-srv). We have
        # special logic there that will return multiple IP addresses for
        # service names.
        dns: 10.77.77.77
        ports:
          - {directory_v1_port}:4000 # ACME
          - {directory_v2_port}:4001 # ACMEv2
          - {challsrvport_mgt_port}:8055 # dns-test-srv updates
        depends_on:
          - bhsm
          - bmysql
        entrypoint: test/entrypoint.sh
        working_dir: /go/src/github.com/letsencrypt/boulder
    bhsm:
        # To minimize fetching this should be the same version used above
        image: letsencrypt/boulder-tools-go{travis_go_version}:{boulder_version}
        environment:
            PKCS11_DAEMON_SOCKET: tcp://0.0.0.0:5657
        command: /usr/local/bin/pkcs11-daemon /usr/lib/softhsm/libsofthsm2.so
        expose:
          - 5657
        networks:
          bluenet_{node}:
            aliases:
              - boulder-hsm
    bmysql:
        image: mariadb:10.3
        networks:
          bluenet_{node}:
            aliases:
              - boulder-mysql
        environment:
            MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
        command: mysqld --bind-address=0.0.0.0
        logging:
            driver: none
networks:
  bluenet_{node}:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.77.77.0/24
  rednet_{node}:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.88.88.0/24
'''.format(travis_go_version=TRAVIS_GO_VERSION,
           boulder_version=BOULDER_VERSION,
           node=params['node'],
           directory_v1_port=params['directory_v1_port'],
           directory_v2_port=params['directory_v2_port'],
           challsrvport_mgt_port=params['challsrvport_mgt_port'])

    with open(join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    with open(join(workspace, 'boulder/test/config/va.json'), 'r') as file:
        data = file.read()

    data = re.sub('"httpPort": 5002,', '"httpPort": {0},'.format(params['http_01_port']), data)
    data = re.sub('"httpsPort": 5001,', '"httpsPort": {0},'.format(params['https_01_port']), data)
    data = re.sub('"tlsPort": 5001', '"tlsPort": {0}'.format(params['https_01_port']), data)

    with open(join(workspace, 'boulder/test/config/va.json'), 'w') as file:
        file.write(data)

    for root, dirs, files in os.walk(join(workspace)):
        for name in files:
            try:
                with open(join(root, name), 'r') as file:
                    data = file.read()

                data = re.sub('10.77.77', params['bluenet_network'], data)
                data = re.sub('10.88.88', params['rednet_network'], data)
                data = re.sub('boulder-hsm', 'boulder-hsm_{0}'.format(params['node']), data)
                data = re.sub('boulder-mysql', 'boulder-mysql_{0}'.format(params['node']), data)

                with open(join(root, name), 'w') as file:
                    file.write(data)
            except UnicodeDecodeError:
                pass

    os.rename(join(workspace, 'boulder/test/rate-limit-policies-b.yml'),
              join(workspace, 'boulder/test/rate-limit-policies.yml'))

    return 'http://localhost:{0}/directory'.format(
        params['directory_v2_port'] if acme_v2 else params['directory_v1_port'])


def _setup_pebble(workspace, params, strict=False):
    data = '''\
version: '3'
services:
  pebble:
    build:
      context: ./pebble
      dockerfile: docker/pebble/Dockerfile
    command: pebble -config /test/config/pebble-config.json {strict} -dnsserver {bluenet_network}.3:8053
    ports:
      # HTTPS ACME API
      - {directory_v2_port}:14000
    networks:
      acmenet_{node}:
        ipv4_address: {bluenet_network}.2
    depends_on:
      - challtestsrv
  challtestsrv:
    build:
      context: ./pebble
      dockerfile: docker/pebble-challtestsrv/Dockerfile
    ports:
      # HTTP Management Interface
      - {challsrvport_mgt_port}:8055
    networks:
      acmenet_{node}:
        ipv4_address: {bluenet_network}.3
networks:
  acmenet_{node}:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: {bluenet_network}.0/24
'''.format(node=params['node'],
           bluenet_network=params['bluenet_network'],
           challsrvport_mgt_port=params['challsrvport_mgt_port'],
           directory_v2_port=params['directory_v2_port'],
           strict='-strict' if strict else '')

    with open(join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    data = '''
{{
  "pebble": {{
    "listenAddress": "0.0.0.0:14000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": {http_01_port},
    "tlsPort": {https_01_port}
  }}
}}
'''.format(http_01_port=params['http_01_port'], https_01_port=params['https_01_port'])

    with open(join(workspace, 'pebble/test/config/pebble-config.json'), 'w') as file:
        file.write(data)

    return 'https://localhost:{0}/dir'.format(params['directory_v2_port'])


def launch_command(command, cwd=os.getcwd()):
    try:
        subprocess.check_call(command, stderr=subprocess.STDOUT, cwd=cwd, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output)
        raise
