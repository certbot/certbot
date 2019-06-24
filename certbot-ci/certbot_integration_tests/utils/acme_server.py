#!/usr/bin/env python
"""Module to setup an ACME CA server environment able to run multiple tests in parallel"""
from __future__ import print_function
import json
import tempfile
import time
import os
import subprocess
import shutil
import sys
from os.path import join

import requests
import yaml

from certbot_integration_tests.utils import misc, proxy
from certbot_integration_tests.utils.constants import *


class ACMEServer(object):
    """
    Handler exposing methods to start and stop the ACME server, and get its configuration
    (eg. challenges ports). ACMEServer is also a context manager, and so can be used to
    ensure ACME server is started/stopped upon context enter/exit.
    """
    def __init__(self, acme_xdist, start, server_cleanup):
        self._proxy_process = None
        self._server_cleanup = server_cleanup
        self.acme_xdist = acme_xdist
        self.start = start

    def stop(self):
        if self._proxy_process:
            self._proxy_process.terminate()
            self._proxy_process.wait()
        self._server_cleanup()

    def __enter__(self):
        self._proxy_process = self.start()
        return self.acme_xdist

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


def setup_acme_server(acme_server, nodes, proxy=True):
    """
    This method will setup an ACME CA server and an HTTP reverse proxy instance, to allow parallel
    execution of integration tests against the unique http-01 port expected by the ACME CA server.
    Typically all pytest integration tests will be executed in this context.
    An ACMEServer instance will be returned, giving access to the ports and directory url to use
    for each pytest node, and its start and stop methods are appropriately configured to
    respectively start the server, and stop it with proper resources cleanup.
    :param str acme_server: the type of acme server used (boulder-v1, boulder-v2 or pebble)
    :param str[] nodes: list of node names that will be setup by pytest xdist
    :param bool proxy: set to False to not start the HTTP proxy
    :return: a properly configured ACMEServer instance
    :rtype: ACMEServer
    """
    acme_type = 'pebble' if acme_server == 'pebble' else 'boulder'
    acme_xdist = _construct_acme_xdist(acme_server, nodes)
    workspace, server_cleanup = _construct_workspace(acme_type)

    def start():
        proxy_process = _prepare_http_proxy(acme_xdist) if proxy else None
        _prepare_acme_server(workspace, acme_type, acme_xdist)

        return proxy_process

    return ACMEServer(acme_xdist, start, server_cleanup)


def _construct_acme_xdist(acme_server, nodes):
    """Generate and return the acme_xdist dict"""
    acme_xdist = {'acme_server': acme_server, 'challtestsrv_port': CHALLTESTSRV_PORT}

    # Directory and ACME port are set implicitly in the docker-compose.yml files of Boulder/Pebble.
    if acme_server == 'pebble':
        acme_xdist['directory_url'] = PEBBLE_DIRECTORY_URL
    else:  # boulder
        acme_xdist['directory_url'] = BOULDER_V2_DIRECTORY_URL \
            if acme_server == 'boulder-v2' else BOULDER_V1_DIRECTORY_URL

    acme_xdist['http_port'] = {node: port for (node, port)
                               in zip(nodes, range(5200, 5200 + len(nodes)))}
    acme_xdist['https_port'] = {node: port for (node, port)
                                in zip(nodes, range(5100, 5100 + len(nodes)))}
    acme_xdist['other_port'] = {node: port for (node, port)
                                in zip(nodes, range(5300, 5300 + len(nodes)))}

    return acme_xdist


def _construct_workspace(acme_type):
    """Create a temporary workspace for integration tests stack"""
    workspace = tempfile.mkdtemp()

    def cleanup():
        """Cleanup function to call that will teardown relevant dockers and their configuration."""
        print('=> Tear down the {0} instance...'.format(acme_type))
        instance_path = join(workspace, acme_type)
        try:
            if os.path.isfile(join(instance_path, 'docker-compose.yml')):
                _launch_command(['docker-compose', 'down'], cwd=instance_path)
        except subprocess.CalledProcessError:
            pass
        print('=> Finished tear down of {0} instance.'.format(acme_type))

        if acme_type == 'boulder' and os.path.exists(os.path.join(workspace, 'boulder')):
            # Boulder docker generates build artifacts owned by root user with 0o744 permissions.
            # If we started the acme server from a normal user that has access to the Docker
            # daemon, this user will not be able to delete these artifacts from the host.
            # We need to do it through a docker.
            _launch_command(['docker', 'run', '--rm', '-v', '{0}:/workspace'.format(workspace),
                             'alpine', 'rm', '-rf', '/workspace/boulder'])

        shutil.rmtree(workspace)

    return workspace, cleanup


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


def _prepare_http_proxy(acme_xdist):
    """Configure and launch an HTTP proxy"""
    print('=> Configuring the HTTP proxy...')
    mapping = {r'.+\.{0}\.wtf'.format(node): 'http://127.0.0.1:{0}'.format(port)
               for node, port in acme_xdist['http_port'].items()}
    command = [sys.executable, proxy.__file__, str(HTTP_01_PORT), json.dumps(mapping)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print('=> Finished configuring the HTTP proxy.')

    return process


def _launch_command(command, cwd=os.getcwd()):
    """Launch silently an OS command, output will be displayed in case of failure"""
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT, cwd=cwd, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        sys.stderr.write(e.output)
        raise


def main():
    args = sys.argv[1:]
    server_type = args[0] if args else 'pebble'
    possible_values = ('pebble', 'boulder-v1', 'boulder-v2')
    if server_type not in possible_values:
        raise ValueError('Invalid server value {0}, should be one of {1}'
                         .format(server_type, possible_values))

    acme_server = setup_acme_server(server_type, [], False)
    process = None

    try:
        with acme_server as acme_xdist:
            print('--> Instance of {0} is running, directory URL is {0}'
                  .format(acme_xdist['directory_url']))
            print('--> Press CTRL+C to stop the ACME server.')

            docker_name = 'pebble_pebble_1' if 'pebble' in server_type else 'boulder_boulder_1'
            process = subprocess.Popen(['docker', 'logs', '-f', docker_name])

            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        if process:
            process.terminate()
            process.wait()


if __name__ == '__main__':
    main()
