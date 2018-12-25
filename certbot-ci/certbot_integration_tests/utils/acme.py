"""
This module contains all relevant methods to construct in parallel independent acme server
instances. Independent here means that these instances do not see each other, and that each
pytest node will access to only one acme server, that is reserved for this node exclusively.
The mapping between a node and an instance takes the form of a map whose keys are the node names,
and values are dictionaries that contains the ACME directory URL, and ports to use to validate
each available challenge.
"""
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
import traceback
from os.path import join, exists

import requests

from certbot_integration_tests.utils import misc
from acme.magic_typing import List

# Current boulder version to test. Pebble do not have it, so master will always be executed.
BOULDER_VERSION = '2018-12-13'
TRAVIS_GO_VERSION = '1.11.2'


def setup_acme_server(acme_config, nodes, repositories_path):
    # type: (dict, List[str], str) -> dict
    """
    Main purpose of this module. This method will ensure that every acme server instance
    is correctly setup and responding. Instances are properly closed and cleaned when
    the Python process exit, using atexit.
    Typically all pytest integration tests will be executed in this context.
    This method returns an object describing ports and directory url to use for each acme
    server with the relevant pytest xdist node.
    :param dict acme_config: adict describing the current acme server characteristics to setup.
    :param str[] nodes: list of nodes name that will be setup by pytest xdist
    :param str repositories_path: the persistent repository path to use to retrieve
                                  acme server source code
    :return: a dict describing the acme server instances that have been setup for the nodes
    :rtype: dict
    """
    acme_type = acme_config['type']
    acme_xdist = {'master': {}}

    with _prepare_repository(repositories_path, acme_type) as repo_path:
        print('=> Warming up Docker engine ...')
        _warm_up_docker(acme_type)
        # All acme servers setup are run in parallel, to speed up the processing
        pool = multiprocessing.Pool(processes=len(nodes))
        expected_results = [_setup_one_node(index, node, acme_config, pool, repo_path)
                            for (index, node) in enumerate(nodes)]
        results = [result.get() for result in expected_results]

        if False in results:
            raise ValueError('One instance of {0} did not start correctly.'.format(acme_type))

        # Gather all acme server instances description, and associate one for each node
        for (index, node) in enumerate(nodes):
            acme_xdist[node] = results[index]

        return acme_xdist


@contextlib.contextmanager
def _prepare_repository(repositories_path, acme_type):
    # type: (str, str) -> str
    """
    This contextmanager will construct a local GIT repository of the relevant ACME server,
    either pebble or boulder. And ensure to clean up correctly when context is destroyed if
    something goes wrong. Otherwise the repository is conserved, to speed up further executions.
    :param str repositories_path: the repositories path to use to store the GIT repo.
    :param str acme_type: type of acme server, pebble or boulder
    :return: the repository path
    :rtype: str
    """
    print('=> Preparing GIT repositories...')
    repo_path = join(repositories_path, acme_type)

    try:
        if not exists(repo_path):
            _launch_command(['git', 'clone', 'https://github.com/letsencrypt/{0}'.format(acme_type),
                            '--single-branch', '--depth=1', repo_path])

        _launch_command(['git', 'clean', '-fd'], cwd=repo_path)
        _launch_command(['git', 'checkout', '-B', 'master', 'origin/master'], cwd=repo_path)
        _launch_command(['git', 'pull'], cwd=repo_path)
        print('=> GIT repositories ready.')
        yield repo_path
    except (OSError, subprocess.CalledProcessError):
        try:
            shutil.rmtree(repo_path)
        except OSError:
            pass


def _warm_up_docker(acme_type):
    # type: (str) -> None
    """
    This function will download the relevant docker files before any docker-compose call,
    to speed up theses calls. Indeed in a paralleled execution, a given image could be
    downloaded several times in parallel, which is not efficient.
    :param str acme_type: the acme server type, pebble or boulder
    """
    if acme_type == 'boulder':
        _launch_command(['docker', 'pull', 'letsencrypt/boulder-tools-go{0}:{1}'
                       .format(TRAVIS_GO_VERSION, BOULDER_VERSION)])
        _launch_command(['docker', 'pull', 'mariadb:10.3'])
    else:
        _launch_command(['docker', 'pull', 'golang:1.11-alpine'])


def _setup_one_node(index, node, acme_config, pool, repo_path):
    # type: (int, str, dict, multiprocessing.Pool, str) -> multiprocessing.pool.AsyncResult
    """
    Build and start an acme server for one node.
    This implies to create ad-hoc docker-compose.yml, launched it, wait for the dockers to be up,
    and setup a safe teardown at the end of the integration tests campaign execution.
    When the server is up, the relevant acme server config will be asynchronously returned
    to the caller.
    :param int index: index of current node
    :param str node: name of current node
    :param dict acme_config: configuration of acme server to setup
    :param multiprocessing.Pool pool: the asynchronous execution pool from
                                      which result must be returned
    :param str repo_path: GIT repository path of the acme server sources
    :return: an promise containing the acme server characteristics in case of success
    :rtype: multiprocessing.pool.AsyncResult
    """
    acme_type = acme_config['type']
    print('=> Setting up a {0} instance ({1})...'.format(acme_type, node))
    workspace = tempfile.mkdtemp()

    def cleanup():
        """
        The cleanup function to call that will teardown relevant dockers and their configuration.
        """
        print('=> Tear down the {0} instance ({1})...'.format(acme_type, node))

        try:
            if os.path.isfile(join(workspace, 'docker-compose.yml')):
                _launch_command(['docker-compose', 'down'], cwd=workspace)
        except subprocess.CalledProcessError:
            pass
        finally:
            try:
                shutil.rmtree(workspace)
            except IOError:
                pass

        print('=> One {0} instance stopped ({1}).'.format(acme_type, node))

    # Here with atexit we ensure that clean function is called no matter what.
    atexit.register(cleanup)

    return pool.apply_async(_async_work, (workspace, index, acme_config, node, repo_path))


def _async_work(workspace, index, acme_config, node, repo_path):
    """
    Asynchronous part of the work to execute to setup an acme server.
    It is here that the ad-hoc docker-compose.yml and its execution will be done.
    The exact content of the docker-compose.yml depends on the acme server type, and is delegated
    to a specialised task.
    :param str workspace: temporary directory where all docker setup will be done
    :param int index: index of current node
    :param dict acme_config: dict describing the acme server to setup
    :param str node: name of current node
    :param str repo_path: path to the GIT repository of current acme server sources
    :return: the acme server characteristics in case of success, false otherwise
    :rtype: dict
    """
    acme_type = acme_config['type']
    try:
        # Each acme server is assigned specific ports, to avoid any collision between them and allow
        # full integration tests paralleled execution.
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

        # Current acme servers sources are copied into the temporary workspace, to allow
        # customisations to a specific acme server instance.
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

        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=workspace)

        print('=> Waiting for {0} instance to respond ({1})...'.format(acme_type, node))

        try:
            # ACME servers can take a long time to be ready to server.
            # This is particulary true with Boulder (1 min in average).
            # So we really wait for the directory url to respond to be sure that server is ready.
            misc.check_until_timeout(directory_url)
        except ValueError:
            return False

        # Configure challtestsrv to answer any A record request with ip of the docker host.
        response = requests.post('http://localhost:{0}/set-default-ipv4'
                                 .format(params['challsrvport_mgt_port']),
                                 '{{"ip":"{0}.1"}}'.format(params['bluenet_network']))
        response.raise_for_status()

        print('=> One {0} instance ready ({1}).'.format(acme_type, node))

        # The xdist object contains everything needed by a pytest method to execute tests against the
        # ACME server instance (http/tls ports, directory url, fake dns server and so one)
        return xdist
    except Exception as e:
        print('Error while setting up the {0} instance ({1}):'.format(acme_type, node))
        print(e)
        traceback.print_exc()
        return False


def _setup_boulder(workspace, params, acme_v2):
    # type: (str, dict, bool) -> str
    """
    Specific docker-compose.yml to setup Boulder.
    Boulder is not suited well for integration tests, so customization is quite complex.
    Several services layers are needed, and some hard-coded values must be modified from the
    source code before dockers are built.
    :param str workspace: Path of current workspace where the dockers will be built and launched
    :param dict params: a dict of all customisations to apply to this particular boulder instance
    :param bool acme_v2: True if the boulder instance should server the ACME v2 protocol
    :return: the directory url of this boulder instance
    :rtype: str
    """
    data = '''
version: '3'
services:
    boulder:
        # To minimize fetching this should be the same version used below
        image: letsencrypt/boulder-tools-go{travis_go_version}:{boulder_version}
        environment:
            FAKE_DNS: 127.0.0.1
            PKCS11_PROXY_SOCKET: tcp://boulder-hsm:5657
            BOULDER_CONFIG_DIR: test/config
        volumes:
          - ./boulder:/go/src/github.com/letsencrypt/boulder
          - ./boulder/.gocache:/root/.cache/go-build
        networks:
          bluenet:
            ipv4_address: 10.77.77.77
            aliases:
              - sa1.boulder
              - ca1.boulder
              - ra1.boulder
              - va1.boulder
              - publisher1.boulder
              - ocsp-updater.boulder
              - admin-revoker.boulder
          rednet:
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
          bluenet:
            aliases:
              - boulder-hsm
    bmysql:
        image: mariadb:10.3
        networks:
          bluenet:
            aliases:
              - boulder-mysql
        environment:
            MYSQL_ALLOW_EMPTY_PASSWORD: "yes"
        command: mysqld --bind-address=0.0.0.0
        logging:
            driver: none
networks:
  bluenet:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.77.77.0/24
  rednet:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 10.88.88.0/24
'''.format(travis_go_version=TRAVIS_GO_VERSION,
           boulder_version=BOULDER_VERSION,
           directory_v1_port=params['directory_v1_port'],
           directory_v2_port=params['directory_v2_port'],
           challsrvport_mgt_port=params['challsrvport_mgt_port'])

    with open(join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    # Here we will have some reprocessing to modify inplace boulder source code
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

    # In particular this allow Boulder to ignore usual limit rate policies, useful to execute
    # a lot of repetitive operations on the server instance.
    os.rename(join(workspace, 'boulder/test/rate-limit-policies-b.yml'),
              join(workspace, 'boulder/test/rate-limit-policies.yml'))

    # Watch out to use the correct port, as Boulder support both ACME v1 amd v2
    return 'http://localhost:{0}/directory'.format(
        params['directory_v2_port'] if acme_v2 else params['directory_v1_port'])


def _setup_pebble(workspace, params, strict=False):
    # type: (str, dict, bool) -> str
    """
    Specific docker-compose.yml to setup Pebble.
    Boulder is not suited well suited for integration tests. All that is required, apart the ad-hoc
    docker-compose.yml, is to provide a custom conf file pebble-config.json.
    :param str workspace: Path of current workspace where the dockers will be built and launched
    :param dict params: a dict of all customisations to apply to this particular pebble instance
    :param strict: True if pebble needs to be run in strict mode
    :return: the directory url of this boulder instance
    :rtype: str
    """
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
      acmenet:
        ipv4_address: {bluenet_network}.2
    depends_on:
      - challtestsrv
  challtestsrv:
    build:
      context: ./pebble
      dockerfile: docker/pebble-challtestsrv/Dockerfile
    command: pebble-challtestsrv -defaultIPv6 "" -defaultIPv4 {bluenet_network}.3
    ports:
      # HTTP Management Interface
      - {challsrvport_mgt_port}:8055
    networks:
      acmenet:
        ipv4_address: {bluenet_network}.3
networks:
  acmenet:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: {bluenet_network}.0/24
'''.format(bluenet_network=params['bluenet_network'],
           challsrvport_mgt_port=params['challsrvport_mgt_port'],
           directory_v2_port=params['directory_v2_port'],
           strict='-strict' if strict else '')

    with open(join(workspace, 'docker-compose.yml'), 'w') as file:
        file.write(data)

    # After registering the ad-hoc docker-compose.yml file, all customisations are contained
    # in a pebble-config.json file, that is written in the copied sources.
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

    # No ACME v1 here. However, directory is server under HTTPS
    return 'https://localhost:{0}/dir'.format(params['directory_v2_port'])


def _launch_command(command, cwd=os.getcwd()):
    # type: (List[str], str) -> None
    """
    Launch a subprocess command, turning off all output, and raising and exception if anything
    goes wrong with a print of the captured output.
    :param str[] command: the command to launch
    :param str cwd: workspace path to use for this command
    """
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT, cwd=cwd, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output)
        raise
