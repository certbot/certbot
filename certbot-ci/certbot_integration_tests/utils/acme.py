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
import contextlib
import shutil
import sys
import time
from os.path import join, exists

import requests
import json

from certbot_integration_tests.utils import misc

# Current boulder version to test. Pebble do not have it, so master will always be executed.
BOULDER_VERSION = '2018-12-13'
TRAVIS_GO_VERSION = '1.11.2'


def setup_acme_server(acme_config, nodes, repositories_path):
    acme_type = acme_config['type']
    acme_xdist = _construct_acme_xdist(acme_type, acme_config['option'], nodes)
    workspace = _construct_workspace(acme_type)

    with _prepare_repository(repositories_path, acme_type) as repo_path:
        _prepare_gobetween_proxy(workspace, acme_xdist)
        _prepare_traefik_proxy(workspace, acme_xdist)
        _prepare_acme_server(repo_path, workspace, acme_type, acme_xdist)

    time.sleep(800)


def _construct_acme_xdist(acme_type, acme_option, nodes):
    acme_xdist = {'challtestsrv_port': 8055}

    if acme_type == 'pebble':
        acme_xdist['directory_url'] = 'https://localhost:14000/dir'
    else:  # boulder
        port = 4001 if acme_option == 'v2' else 4000
        acme_xdist['directory_url'] = 'http://localhost:{0}/directory'.format(port)

    acme_xdist['acme_subnet'] = '10.77.77' if acme_type == 'boulder' else '10.30.50.0'
    acme_xdist['http_port'] = {node: port for (node, port)
                               in zip(nodes, range(5200, 5200 + len(nodes)))}
    acme_xdist['https_port'] = {node: port for (node, port)
                                in zip(nodes, range(5100, 5100 + len(nodes)))}

    return acme_xdist


def _construct_workspace(acme_type):
    workspace = tempfile.mkdtemp()

    def cleanup():
        """
        The cleanup function to call that will teardown relevant dockers and their configuration.
        """
        try:
            for instance in [acme_type, 'traefik', 'gobetween']:
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


def _prepare_acme_server(repo_path, workspace, acme_type, acme_xdist):
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

        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=instance_path)

        print('=> Waiting for {0} instance to respond...'.format(acme_type))

        misc.check_until_timeout(acme_xdist['directory_url'])

        # Configure challtestsrv to answer any A record request with ip of the docker host.
        response = requests.post('http://localhost:{0}/set-default-ipv4'
                                 .format(acme_xdist['challtestsrv_port']),
                                 '{{"ip":"{0}.1"}}'.format(acme_xdist['acme_subnet']))
        response.raise_for_status()

        print('=> Finished {0} instance deployment.'.format(acme_type))
    except Exception as e:
        print('Error while setting up {0} instance.'.format(acme_type))
        raise


def _prepare_traefik_proxy(workspace, acme_xdist):
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
                    'backend': node,
                    'routes': {node: {'rule': '{{subdomain:.+}}.{0}.wtf'.format(node)}}
                } for node in acme_xdist['http_port'].keys()
            }
        }

        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=instance_path)
        misc.check_until_timeout('http://localhost:8056/api')

        requests.put('http://localhost:8056/api/providers/rest', data=json.dumps(config)).raise_for_status()

        print('=> Finished traefik instance deployment.')
    except Exception as e:
        print('Error while setting up traefik instance.')
        raise


def _prepare_gobetween_proxy(workspace, acme_xdist):
    print('=> Starting gobetween instance deployment...')
    try:
        instance_path = join(workspace, 'gobetween')
        os.mkdir(instance_path)

        with open(join(instance_path, 'docker-compose.yml'), 'w') as file_h:
            file_h.write('''\
    version: '3'
    services:
      gobetween:
        image: yyyar/gobetween
        command: /usr/bin/gobetween -c /etc/gobetween/conf/gobetween.json -f json
        ports:
          - "5001:5001"
        volumes:
          - {0}:/etc/gobetween/conf/gobetween.json:rw
        networks:
          gobetweennet:
            ipv4_address: 10.44.44.2
    networks:
      gobetweennet:
        driver: bridge
        ipam:
          config:
            - subnet: 10.44.44.0/24
    '''.format(join(instance_path, 'gobetween.json')))

            config = {
                'servers': {
                    'default': {
                        'bind': ':5001',
                        'sni': {'hostname_matching_strategy': 'regexp'},
                        'discovery': {
                            'kind': 'static',
                            'static_list': [r'10.44.44.1:{0} weight=1 sni=.+\.{1}\.wtf'.format(port, node)
                                            for node, port in acme_xdist['http_port'].items()]
                        }
                    }
                }
            }

        with open(join(instance_path, 'gobetween.json'), 'w') as file_h:
            file_h.write(json.dumps(config))

        _launch_command(['docker-compose', 'up', '--force-recreate', '-d'], cwd=instance_path)

        print('=> Finished gobetween instance deployment.')
    except Exception as e:
        print('Error while setting up gobetween instance.')
        raise


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
