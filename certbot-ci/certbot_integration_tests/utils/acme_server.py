#!/usr/bin/env python
"""Module to setup an ACME CA server environment able to run multiple tests in parallel"""
from __future__ import print_function

import errno
import json
import os
from os.path import join
import shutil
import subprocess
import sys
import tempfile
import time

import requests

from certbot_integration_tests.utils import misc
from certbot_integration_tests.utils import pebble_artifacts
from certbot_integration_tests.utils import proxy
from certbot_integration_tests.utils.constants import *


class ACMEServer(object):
    """
    ACMEServer configures and handles the lifecycle of an ACME CA server and an HTTP reverse proxy
    instance, to allow parallel execution of integration tests against the unique http-01 port
    expected by the ACME CA server.
    Typically all pytest integration tests will be executed in this context.
    ACMEServer gives access the acme_xdist parameter, listing the ports and directory url to use
    for each pytest node. It exposes also start and stop methods in order to start the stack, and
    stop it with proper resources cleanup.
    ACMEServer is also a context manager, and so can be used to ensure ACME server is started/stopped
    upon context enter/exit.
    """
    def __init__(self, acme_server, nodes, http_proxy=True, stdout=False):
        """
        Create an ACMEServer instance.
        :param str acme_server: the type of acme server used (boulder-v1, boulder-v2 or pebble)
        :param list nodes: list of node names that will be setup by pytest xdist
        :param bool http_proxy: if False do not start the HTTP proxy
        :param bool stdout: if True stream all subprocesses stdout to standard stdout
        """
        self._construct_acme_xdist(acme_server, nodes)

        self._acme_type = 'pebble' if acme_server == 'pebble' else 'boulder'
        self._proxy = http_proxy
        self._workspace = tempfile.mkdtemp()
        self._processes = []
        self._stdout = sys.stdout if stdout else open(os.devnull, 'w')

    def start(self):
        """Start the test stack"""
        try:
            if self._proxy:
                self._prepare_http_proxy()
            if self._acme_type == 'pebble':
                self._prepare_pebble_server()
            if self._acme_type == 'boulder':
                self._prepare_boulder_server()
        except BaseException as e:
            self.stop()
            raise e

    def stop(self):
        """Stop the test stack, and clean its resources"""
        print('=> Tear down the test infrastructure...')
        try:
            for process in self._processes:
                try:
                    process.terminate()
                except OSError as e:
                    # Process may be not started yet, so no PID and terminate fails.
                    # Then the process never started, and the situation is acceptable.
                    if e.errno != errno.ESRCH:
                        raise
            for process in self._processes:
                process.wait()

            if os.path.exists(os.path.join(self._workspace, 'boulder')):
                # Boulder docker generates build artifacts owned by root with 0o744 permissions.
                # If we started the acme server from a normal user that has access to the Docker
                # daemon, this user will not be able to delete these artifacts from the host.
                # We need to do it through a docker.
                process = self._launch_process(['docker', 'run', '--rm', '-v',
                                                '{0}:/workspace'.format(self._workspace),
                                                'alpine', 'rm', '-rf', '/workspace/boulder'])
                process.wait()
        finally:
            if os.path.exists(self._workspace):
                shutil.rmtree(self._workspace)
        if self._stdout != sys.stdout:
            self._stdout.close()
        print('=> Test infrastructure stopped and cleaned up.')

    def __enter__(self):
        self.start()
        return self.acme_xdist

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _construct_acme_xdist(self, acme_server, nodes):
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

        self.acme_xdist = acme_xdist

    def _prepare_pebble_server(self):
        """Configure and launch the Pebble server"""
        print('=> Starting pebble instance deployment...')
        pebble_path, challtestsrv_path, pebble_config_path = pebble_artifacts.fetch(self._workspace)

        # Configure Pebble at full speed (PEBBLE_VA_NOSLEEP=1) and not randomly refusing valid
        # nonce (PEBBLE_WFE_NONCEREJECT=0) to have a stable test environment.
        environ = os.environ.copy()
        environ['PEBBLE_VA_NOSLEEP'] = '1'
        environ['PEBBLE_WFE_NONCEREJECT'] = '0'
        environ['PEBBLE_AUTHZREUSE'] = '100'
        environ['PEBBLE_ALTERNATE_ROOTS'] = str(PEBBLE_ALTERNATE_ROOTS)

        self._launch_process(
            [pebble_path, '-config', pebble_config_path, '-dnsserver', '127.0.0.1:8053', '-strict'],
            env=environ)

        self._launch_process(
            [challtestsrv_path, '-management', ':{0}'.format(CHALLTESTSRV_PORT), '-defaultIPv6', '""',
             '-defaultIPv4', '127.0.0.1', '-http01', '""', '-tlsalpn01', '""', '-https01', '""'])

        # pebble_ocsp_server is imported here and not at the top of module in order to avoid a useless
        # ImportError, in the case where cryptography dependency is too old to support ocsp, but
        # Boulder is used instead of Pebble, so pebble_ocsp_server is not used. This is the typical
        # situation of integration-certbot-oldest tox testenv.
        from certbot_integration_tests.utils import pebble_ocsp_server
        self._launch_process([sys.executable, pebble_ocsp_server.__file__])

        # Wait for the ACME CA server to be up.
        print('=> Waiting for pebble instance to respond...')
        misc.check_until_timeout(self.acme_xdist['directory_url'])

        print('=> Finished pebble instance deployment.')

    def _prepare_boulder_server(self):
        """Configure and launch the Boulder server"""
        print('=> Starting boulder instance deployment...')
        instance_path = join(self._workspace, 'boulder')

        # Load Boulder from git, that includes a docker-compose.yml ready for production.
        process = self._launch_process(['git', 'clone', 'https://github.com/letsencrypt/boulder',
                                        '--single-branch', '--depth=1', instance_path])
        process.wait()

        # Allow Boulder to ignore usual limit rate policies, useful for tests.
        os.rename(join(instance_path, 'test/rate-limit-policies-b.yml'),
                  join(instance_path, 'test/rate-limit-policies.yml'))

        try:
            # Launch the Boulder server
            self._launch_process(['docker-compose', 'up', '--force-recreate'], cwd=instance_path)

            # Wait for the ACME CA server to be up.
            print('=> Waiting for boulder instance to respond...')
            misc.check_until_timeout(self.acme_xdist['directory_url'], attempts=300)

            # Configure challtestsrv to answer any A record request with ip of the docker host.
            response = requests.post('http://localhost:{0}/set-default-ipv4'.format(CHALLTESTSRV_PORT),
                                     json={'ip': '10.77.77.1'})
            response.raise_for_status()
        except BaseException:
            # If we failed to set up boulder, print its logs.
            print('=> Boulder setup failed. Boulder logs are:')
            process = self._launch_process(['docker-compose', 'logs'], cwd=instance_path, force_stderr=True)
            process.wait()
            raise

        print('=> Finished boulder instance deployment.')

    def _prepare_http_proxy(self):
        """Configure and launch an HTTP proxy"""
        print('=> Configuring the HTTP proxy...')
        mapping = {r'.+\.{0}\.wtf'.format(node): 'http://127.0.0.1:{0}'.format(port)
                   for node, port in self.acme_xdist['http_port'].items()}
        command = [sys.executable, proxy.__file__, str(HTTP_01_PORT), json.dumps(mapping)]
        self._launch_process(command)
        print('=> Finished configuring the HTTP proxy.')

    def _launch_process(self, command, cwd=os.getcwd(), env=None, force_stderr=False):
        """Launch silently a subprocess OS command"""
        if not env:
            env = os.environ
        stdout = sys.stderr if force_stderr else self._stdout
        process = subprocess.Popen(command, stdout=stdout, stderr=subprocess.STDOUT, cwd=cwd, env=env)
        self._processes.append(process)
        return process


def main():
    args = sys.argv[1:]
    server_type = args[0] if args else 'pebble'
    possible_values = ('pebble', 'boulder-v1', 'boulder-v2')
    if server_type not in possible_values:
        raise ValueError('Invalid server value {0}, should be one of {1}'
                         .format(server_type, possible_values))

    acme_server = ACMEServer(server_type, [], http_proxy=False, stdout=True)

    try:
        with acme_server as acme_xdist:
            print('--> Instance of {0} is running, directory URL is {0}'
                  .format(acme_xdist['directory_url']))
            print('--> Press CTRL+C to stop the ACME server.')

            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
