"""Module to setup an ACME CA server environment able to run multiple tests in parallel"""
from __future__ import print_function
import tempfile
import atexit
import os
import subprocess
import shutil
import sys
from os.path import join

import requests
import json
import yaml

from certbot_integration_tests.utils import misc

# These ports are set implicitly in the docker-compose.yml files of Boulder/Pebble.
CHALLTESTSRV_PORT = 8055
HTTP_01_PORT = 5002


def setup_acme_server(acme_server, nodes):
    """
    This method will setup an ACME CA server and an HTTP reverse proxy instance, to allow parallel
    execution of integration tests against the unique http-01 port expected by the ACME CA server.
    Instances are properly closed and cleaned when the Python process exits using atexit.
    Typically all pytest integration tests will be executed in this context.
    This method returns an object describing ports and directory url to use for each pytest node
    with the relevant pytest xdist node.
    :param str acme_server: the type of acme server used (boulder-v1, boulder-v2 or pebble)
    :param str[] nodes: list of node names that will be setup by pytest xdist
    :return: a dict describing the challenge ports that have been setup for the nodes
    :rtype: dict
    """
    acme_type = 'pebble' if acme_server == 'pebble' else 'boulder'
    acme_xdist = _construct_acme_xdist(acme_server, nodes)
    workspace = _construct_workspace(acme_type)

    _prepare_traefik_proxy(workspace, acme_xdist)
    _prepare_acme_server(workspace, acme_type, acme_xdist)

    return acme_xdist


def _construct_acme_xdist(acme_server, nodes):
    """Generate and return the acme_xdist dict"""
    acme_xdist = {'acme_server': acme_server, 'challtestsrv_port': CHALLTESTSRV_PORT}

    # Directory and ACME port are set implicitly in the docker-compose.yml files of Boulder/Pebble.
    if acme_server == 'pebble':
        acme_xdist['directory_url'] = 'https://localhost:14000/dir'
    else:  # boulder
        port = 4001 if acme_server == 'boulder-v2' else 4000
        acme_xdist['directory_url'] = 'http://localhost:{0}/directory'.format(port)

    acme_xdist['http_port'] = {node: port for (node, port)
                               in zip(nodes, range(5200, 5200 + len(nodes)))}
    acme_xdist['https_port'] = {node: port for (node, port)
                                in zip(nodes, range(5100, 5100 + len(nodes)))}

    return acme_xdist


def _construct_workspace(acme_type):
    """Create a temporary workspace for integration tests stack"""
    workspace = tempfile.mkdtemp()

    def cleanup():
        """Cleanup function to call that will teardown relevant dockers and their configuration."""
        for instance in [acme_type, 'traefik']:
            print('=> Tear down the {0} instance...'.format(instance))
            instance_path = join(workspace, instance)
            try:
                if os.path.isfile(join(instance_path, 'docker-compose.yml')):
                    _launch_command(['docker-compose', 'down'], cwd=instance_path)
            except subprocess.CalledProcessError:
                pass
            print('=> Finished tear down of {0} instance.'.format(acme_type))

        shutil.rmtree(workspace)

    # Here with atexit we ensure that clean function is called no matter what.
    atexit.register(cleanup)

    return workspace


def _prepare_acme_server(workspace, acme_type, acme_xdist):
    """Configure and launch the ACME server, Boulder or Pebble"""
    print('=> Starting {0} instance deployment...'.format(acme_type))
    instance_path = join(workspace, acme_type)
    try:
        # Load Boulder/Pebble from git, that includes a docker-compose.yml ready for production.
        _launch_command(['git', 'clone', 'https://github.com/letsencrypt/{0}'.format(acme_type),
                         '--single-branch', '--depth=1', instance_path])
        if acme_type == 'boulder':
            # Allow Boulder to ignore usual limit rate policies, useful for tests.
            os.rename(join(instance_path, 'test/rate-limit-policies-b.yml'),
                      join(instance_path, 'test/rate-limit-policies.yml'))
        if acme_type == 'pebble':
            # Configure Pebble at full speed (PEBBLE_VA_NOSLEEP=1) and not randomly refusing valid
            # nonce (PEBBLE_WFE_NONCEREJECT=0) to have a stable test environment.
            with open(os.path.join(instance_path, 'docker-compose.yml'), 'r') as file_handler:
                config = yaml.load(file_handler.read())

            config['services']['pebble'].setdefault('environment', [])\
                .extend(['PEBBLE_VA_NOSLEEP=1', 'PEBBLE_WFE_NONCEREJECT=0'])
            with open(os.path.join(instance_path, 'docker-compose.yml'), 'w') as file_handler:
                file_handler.write(yaml.dump(config))

        # Launch the ACME CA server.
        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=instance_path)

        # Wait for the ACME CA server to be up.
        print('=> Waiting for {0} instance to respond...'.format(acme_type))
        misc.check_until_timeout(acme_xdist['directory_url'])

        # Configure challtestsrv to answer any A record request with ip of the docker host.
        acme_subnet = '10.77.77' if acme_type == 'boulder' else '10.30.50'
        response = requests.post('http://localhost:{0}/set-default-ipv4'
                                 .format(acme_xdist['challtestsrv_port']),
                                 json={'ip': '{0}.1'.format(acme_subnet)})
        response.raise_for_status()

        print('=> Finished {0} instance deployment.'.format(acme_type))
    except BaseException:
        print('Error while setting up {0} instance.'.format(acme_type))
        raise


def _prepare_traefik_proxy(workspace, acme_xdist):
    """Configure and launch Traefik, the HTTP reverse proxy"""
    print('=> Starting traefik instance deployment...')
    instance_path = join(workspace, 'traefik')
    traefik_subnet = '10.33.33'
    traefik_api_port = 8056
    try:
        os.mkdir(instance_path)

        with open(join(instance_path, 'docker-compose.yml'), 'w') as file_h:
            file_h.write('''\
version: '3'
services:
  traefik:
    image: traefik
    command: --api --rest
    ports:
      - {http_01_port}:80
      - {traefik_api_port}:8080
    networks:
      traefiknet:
        ipv4_address: {traefik_subnet}.2
networks:
  traefiknet:
    ipam:
      config:
        - subnet: {traefik_subnet}.0/24
'''.format(traefik_subnet=traefik_subnet,
           traefik_api_port=traefik_api_port,
           http_01_port=HTTP_01_PORT))

        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=instance_path)

        misc.check_until_timeout('http://localhost:{0}/api'.format(traefik_api_port))
        config = {
            'backends': {
                node: {
                    'servers': {node: {'url': 'http://{0}.1:{1}'.format(traefik_subnet, port)}}
                } for node, port in acme_xdist['http_port'].items()
            },
            'frontends': {
                node: {
                    'backend': node, 'passHostHeader': True,
                    'routes': {node: {'rule': 'HostRegexp: {{subdomain:.+}}.{0}.wtf'.format(node)}}
                } for node in acme_xdist['http_port'].keys()
            }
        }
        response = requests.put('http://localhost:{0}/api/providers/rest'.format(traefik_api_port),
                                data=json.dumps(config))
        response.raise_for_status()

        print('=> Finished traefik instance deployment.')
    except BaseException:
        print('Error while setting up traefik instance.')
        raise


def _launch_command(command, cwd=os.getcwd()):
    """Launch silently an OS command, output will be displayed in case of failure"""
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT, cwd=cwd, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output)
        raise
