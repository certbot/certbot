"""Module to setup an ACME CA server environment able to run multiple tests in parallel"""
from __future__ import print_function
import tempfile
import atexit
import os
import subprocess
import contextlib
import shutil
import sys
from os.path import join, exists

import requests
import json

from certbot_integration_tests.utils import misc


def setup_acme_server(acme_config, nodes, repositories_path):
    """
    This method will setup an ACME CA server and a HTTP reverse proxy instances, to allow parallel
    execution of integration tests against the unique http-01 port expected by the ACME CA server.
    Instances are properly closed and cleaned when the Python process exits using atexit.
    Typically all pytest integration tests will be executed in this context.
    This method returns an object describing ports and directory url to use for each pytest node
    with the relevant pytest xdist node.
    :param dict acme_config: a dict describing the current acme server characteristics to setup.
    :param str[] nodes: list of nodes name that will be setup by pytest xdist
    :param str repositories_path: the persistent repository path to use to retrieve
                                  acme server source code
    :return: a dict describing the challenges ports that have been setup for the nodes
    :rtype: dict
    """
    acme_type = acme_config['type']
    acme_option = acme_config['option']
    acme_xdist = _construct_acme_xdist(acme_type, acme_option, nodes)
    workspace = _construct_workspace(acme_type)

    with _prepare_repository(repositories_path, acme_type) as repo_path:
        _prepare_traefik_proxy(workspace, acme_xdist)
        _prepare_acme_server(repo_path, workspace, acme_type, acme_option, acme_xdist)

    return acme_xdist


def _construct_acme_xdist(acme_type, acme_option, nodes):
    """Generate and return the acme_xdist dict"""
    acme_xdist = {'challtestsrv_port': 8055}

    if acme_type == 'pebble':
        acme_xdist['directory_url'] = 'https://localhost:14000/dir'
    else:  # boulder
        port = 4001 if acme_option == 'v2' else 4000
        acme_xdist['directory_url'] = 'http://localhost:{0}/directory'.format(port)

    acme_xdist['acme_subnet'] = '10.77.77' if acme_type == 'boulder' else '10.30.50'
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
        try:
            for instance in [acme_type, 'traefik']:
                print('=> Tear down the {0} instance...'.format(instance))
                instance_path = join(workspace, instance)
                try:
                    if os.path.isfile(join(instance_path, 'docker-compose.yml')):
                        _launch_command(['docker-compose', 'down'], cwd=instance_path)
                except subprocess.CalledProcessError:
                    pass
                print('=> Finished tear down of {0} instance.'.format(acme_type))
        finally:
            shutil.rmtree(workspace)

    # Here with atexit we ensure that clean function is called no matter what.
    atexit.register(cleanup)

    return workspace


def _prepare_acme_server(repo_path, workspace, acme_type, acme_option, acme_xdist):
    """Configure and launch the ACME server, Boulder or Pebble"""
    print('=> Starting {0} instance deployment...'.format(acme_type))
    try:
        # Current acme servers sources are copied into the temporary workspace, to allow
        # customisations to a specific acme server instance.
        ignore = shutil.ignore_patterns('.git')
        instance_path = join(workspace, acme_type)
        shutil.copytree(repo_path, instance_path, ignore=ignore)

        # This allow Boulder to ignore usual limit rate policies, useful to execute
        # a lot of repetitive operations on the server instance.
        if acme_type == 'boulder':
            os.rename(join(workspace, 'boulder/test/rate-limit-policies-b.yml'),
                      join(workspace, 'boulder/test/rate-limit-policies.yml'))

        # This configure Pebble using precompiled containers.
        if acme_type == 'pebble':
            with open(join(instance_path, 'docker-compose.yml'), 'w') as file_h:
                file_h.write('''\
version: '3'
services:
  pebble:
    image: letsencrypt/pebble
    command: pebble -config /test/config/pebble-config.json {strict} -dnsserver 10.30.50.3:8053
    ports:
      - 14000:14000
    networks:
      acmenet:
        ipv4_address: 10.30.50.2
  challtestsrv:
    image: letsencrypt/pebble-challtestsrv
    command: pebble-challtestsrv -defaultIPv6 "" -defaultIPv4 10.30.50.3
    ports:
      - 8055:8055
    networks:
      acmenet:
        ipv4_address: 10.30.50.3
networks:
  acmenet:
    driver: bridge
    ipam:
      config:
        - subnet: 10.30.50.0/24
'''.format(strict='-strict' if acme_option == 'strict' else ''))

        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=instance_path)

        print('=> Waiting for {0} instance to respond...'.format(acme_type))

        # Wait for the ACME CA server to be up.
        misc.check_until_timeout(acme_xdist['directory_url'])

        # Configure challtestsrv to answer any A record request with ip of the docker host.
        response = requests.post('http://localhost:{0}/set-default-ipv4'
                                 .format(acme_xdist['challtestsrv_port']),
                                 '{{"ip":"{0}.1"}}'.format(acme_xdist['acme_subnet']))
        response.raise_for_status()

        print('=> Finished {0} instance deployment.'.format(acme_type))
    except BaseException:
        print('Error while setting up {0} instance.'.format(acme_type))
        raise


def _prepare_traefik_proxy(workspace, acme_xdist):
    """Configure and launch Traefik, the HTTP reverse proxy"""
    print('=> Starting traefik instance deployment...')
    try:
        instance_path = join(workspace, 'traefik')
        os.mkdir(instance_path)

        with open(join(instance_path, 'docker-compose.yml'), 'w') as file_h:
            file_h.write('''\
version: '3'
services:
  traefik:
    image: traefik
    command: --api --rest
    ports:
      - "5002:80"
      - "8056:8080"
    networks:
      traefiknet:
        ipv4_address: 10.33.33.2
networks:
  traefiknet:
    driver: bridge
    ipam:
      config:
        - subnet: 10.33.33.0/24
''')

        config = {
            'backends': {
                node: {
                    'servers': {node: {'url': 'http://10.33.33.1:{0}'.format(port)}}
                } for node, port in acme_xdist['http_port'].items()
            },
            'frontends': {
                node: {
                    'backend': node, 'passHostHeader': True,
                    'routes': {node: {'rule': 'HostRegexp: {{subdomain:.+}}.{0}.wtf'.format(node)}}
                } for node in acme_xdist['http_port'].keys()
            }
        }

        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=instance_path)
        misc.check_until_timeout('http://localhost:8056/api')

        requests.put('http://localhost:8056/api/providers/rest', data=json.dumps(config)).raise_for_status()

        print('=> Finished traefik instance deployment.')
    except BaseException:
        print('Error while setting up traefik instance.')
        raise


@contextlib.contextmanager
def _prepare_repository(repositories_path, acme_type):
    """Fetch the relevant GIT repository for ACME CA server selected"""
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


def _launch_command(command, cwd=os.getcwd()):
    """Launch silently an OS command, output will be displayed in case of failure"""
    try:
        subprocess.check_call(command, stderr=subprocess.STDOUT, cwd=cwd, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output)
        raise
