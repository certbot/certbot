from __future__ import print_function
import tempfile
import atexit
import os
import subprocess
import shutil
import re
import contextlib
import multiprocessing

from certbot_integration_tests.utils import misc

PEBBLE_VERSION = '2018-11-02'
BOULDER_VERSION = '2018-11-19'
TRAVIS_GO_VERSION = '1.11.2'


@contextlib.contextmanager
def setup_acme_server(acme_server, nodes):
    acme_type = 'Boulder' if 'boulder' in acme_server else 'Pebble'
    acme_xdist = {'master': {}}

    pool = multiprocessing.Pool(processes=len(nodes))
    expected_results = [_setup_one_node(index, node, acme_type, acme_server, pool)
                        for (index, node) in enumerate(nodes)]
    results = [result.get() for result in expected_results]

    if False in results:
        raise ValueError('One instance of {0} did not start correctly.'.format(acme_type))

    for (index, node) in enumerate(nodes):
        acme_xdist[node] = results[index]

    yield acme_xdist


def _setup_one_node(index, node, acme_type, acme_server, pool):
    print('=> Setting up a {0} instance ({1})...'.format(acme_type, node))
    tempdir = tempfile.mkdtemp()
    workspace = os.path.join(tempdir, 'src/github.com/letsencrypt/{0}'.format(acme_type.lower()))

    def cleanup():
        print('=> Tear down the {0} instance ({1}) ...'.format(acme_type, node))

        try:
            if os.path.isfile(os.path.join(workspace, 'docker-compose.yml')):
                subprocess.check_call(['docker-compose', 'down'], cwd=workspace)
        except subprocess.CalledProcessError:
            pass
        finally:
            try:
                #shutil.rmtree(tempdir)
                pass
            except IOError:
                pass

        print('=> {0} instance stopped ({1}).'.format(acme_type, node))

    atexit.register(cleanup)

    return pool.apply_async(_async_work, (workspace, acme_type, index, acme_server, node))


def _async_work(workspace, acme_type, index, acme_server, node):
    os.makedirs(workspace)

    if acme_type == 'Boulder':
        config = _setup_boulder(workspace, index)
    else:
        config = _setup_pebble(workspace,
                               strict=acme_server == 'pebble-strict')

    print('=> Waiting for {0} instance to respond ({1}) ...'.format(acme_type, node))

    try:
        misc.check_until_timeout(config['directory_url'])
    except ValueError:
        return False

    print('=> {0} instance ready.'.format(acme_type))


def _setup_boulder(workspace, index, acme_v2=True):
    tls_sni_01_port = 5000 + 10 * index
    http_01_port = 6000 + 10 * index
    directory_v1_port = 4000 + 10 * index
    directory_v2_port = 7000 + 10 * index
    challsrvport_mgt_port = 8000 + 10 * index

    bluenet_network = '10.77.{0}'.format(index)
    rednet_network = '10.88.{0}'.format(index)

    subprocess.check_call(['git', 'clone', '--depth', '1', '--single-branch',
                           'https://github.com/letsencrypt/boulder', workspace])

    data = '''
version: '3'
services:
    boulder:
        # To minimize fetching this should be the same version used below
        image: letsencrypt/boulder-tools-go{travis_go_version}:{boulder_version}
        environment:
            FAKE_DNS: {bluenet_network}.1
            PKCS11_PROXY_SOCKET: tcp://boulder-hsm:5657
            BOULDER_CONFIG_DIR: test/config
        volumes:
          - .:/go/src/github.com/letsencrypt/boulder
          - ./.gocache:/root/.cache/go-build
        networks:
          bluenet_{index}:
            ipv4_address: {bluenet_network}.77
            aliases:
              - sa1.boulder
              - ca1.boulder
              - ra1.boulder
              - va1.boulder
              - publisher1.boulder
              - ocsp-updater.boulder
              - admin-revoker.boulder
          rednet_{index}:
            ipv4_address: {rednet_network}.88
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
        dns: {bluenet_network}.77
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
          bluenet_{index}:
            aliases:
              - boulder-hsm
    bmysql:
        image: mariadb:10.3
        networks:
          bluenet_{index}:
            aliases:
              - boulder-mysql
        environment:
            MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
        command: mysqld --bind-address=0.0.0.0
        logging:
            driver: none
    netaccess:
        image: letsencrypt/boulder-tools-go{travis_go_version}:{boulder_version}
        networks:
          - bluenet_{index}
        volumes:
          - .:/go/src/github.com/letsencrypt/boulder
        working_dir: /go/src/github.com/letsencrypt/boulder
        entrypoint: test/entrypoint-netaccess.sh
        depends_on:
          - bmysql

networks:
  bluenet_{index}:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: {bluenet_network}.0/24
  rednet_{index}:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: {rednet_network}.0/24
'''.format(travis_go_version=TRAVIS_GO_VERSION,
           boulder_version=BOULDER_VERSION,
           bluenet_network=bluenet_network,
           rednet_network=rednet_network,
           index=index,
           directory_v1_port=directory_v1_port,
           directory_v2_port=directory_v2_port,
           challsrvport_mgt_port=challsrvport_mgt_port)

    with open(os.path.join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    with open(os.path.join(workspace, 'test/config/va.json'), 'r') as file:
        data = file.read()

    data = re.sub('"httpPort": 5002,', '"httpPort": {0},'.format(http_01_port), data)
    data = re.sub('"httpsPort": 5001,', '"httpsPort": {0},'.format(tls_sni_01_port), data)
    data = re.sub('"tlsPort": 5001,', '"tlsPort": {0},'.format(tls_sni_01_port), data)

    with open(os.path.join(workspace, 'test/config/va.json'), 'w') as file:
        file.write(data)

    with open(os.path.join(workspace, 'test/sd-test-srv/main.go'), 'r') as file:
        data = file.read()

    data = re.sub('10.77.77', bluenet_network, data)
    data = re.sub('10.88.88', rednet_network, data)

    with open(os.path.join(workspace, 'test/sd-test-srv/main.go'), 'w') as file:
        file.write(data)

    subprocess.check_call(['docker-compose', 'up', '-d', 'boulder'], cwd=workspace)

    return {
        'directory_url': 'http://localhost:{0}/directory'.format(
            directory_v2_port if acme_v2 else directory_v1_port),
        'tls_sni_01_port': tls_sni_01_port,
        'http_01_port': http_01_port,
        'challsrvtest_mgt_port': challsrvport_mgt_port
    }


def _setup_pebble(workspace, strict=False):
    subprocess.check_call(['git', 'clone', '--depth', '1', '--single-branch',
                           'https://github.com/letsencrypt/boulder',
                           os.path.join(workspace, 'boulder')])
    data = '''
FROM golang:stretch
RUN mkdir -p /go/src/github.com/letsencrypt/boulder
WORKDIR /go/src/github.com/letsencrypt/boulder
COPY . .
RUN go install ./test/challtestsrv/...
'''

    with open(os.path.join(workspace, 'boulder/Dockerfile'), 'w') as file:
        file.write(data)

    data = '''\
version: '3'
services:
  challtestsrv:
    build: ./boulder
    networks:
      bluenet:
        ipv4_address: 10.77.77.78
    ports:
      - 8055:8055
    environment:
      - FAKE_DNS=10.77.77.1
    command: challtestsrv -http01 "" -tlsalpn01 "" -dns01 ":53" -management ":8055"
  pebble:
    image: letsencrypt/pebble:{0}
    command: pebble -dnsserver 10.77.77.78:53 {1}
    networks:
      bluenet:
        ipv4_address: 10.77.77.77
    dns: 10.77.77.78
    ports:
      - 14000:14000
    environment:
      - PEBBLE_VA_NOSLEEP=1
      - PEBBLE_WFE_NONCEREJECT=0
    depends_on:
      - challtestsrv
networks:
  bluenet:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.77.77.0/24

'''.format(PEBBLE_VERSION, '-strict' if strict else '')

    with open(os.path.join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    subprocess.check_call(['docker-compose', 'up', '-d', 'pebble'], cwd=workspace)

    return 'https://localhost:14000/dir'
