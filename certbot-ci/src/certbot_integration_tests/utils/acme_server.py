#!/usr/bin/env python
"""Module to setup an ACME CA server environment able to run multiple tests in parallel"""

import argparse
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from types import TracebackType
from typing import Any
from typing import cast
from typing import Mapping
from typing import Optional

# pylint: disable=wildcard-import,unused-wildcard-import
from certbot_integration_tests.utils import misc
from certbot_integration_tests.utils import pebble_artifacts
from certbot_integration_tests.utils import pebble_ocsp_server
from certbot_integration_tests.utils import proxy
from certbot_integration_tests.utils.constants import DEFAULT_HTTP_01_PORT
from certbot_integration_tests.utils.constants import CHALLTESTSRV_PORT
from certbot_integration_tests.utils.constants import PEBBLE_DIRECTORY_URL
from certbot_integration_tests.utils.constants import PEBBLE_CHALLTESTSRV_URL
from certbot_integration_tests.utils.constants import PEBBLE_ALTERNATE_ROOTS
from certbot_integration_tests.utils.constants import MAX_SUBPROCESS_WAIT


class ACMEServer:
    """
    ACMEServer configures and handles the lifecycle of an ACME CA server and an HTTP reverse proxy
    instance, to allow parallel execution of integration tests against the unique http-01 port
    expected by the ACME CA server.
    Typically all pytest integration tests will be executed in this context.
    ACMEServer gives access the acme_xdist parameter, listing the ports and directory url to use
    for each pytest node. It exposes also start and stop methods in order to start the stack, and
    stop it with proper resources cleanup.
    ACMEServer is also a context manager, and so can be used to ensure ACME server is
    started/stopped upon context enter/exit.
    """
    def __init__(self, nodes: list[str], http_proxy: bool = True,
                 stdout: bool = False, dns_server: Optional[str] = None,
                 http_01_port: Optional[int] = None) -> None:
        """
        Create an ACMEServer instance.
        :param list nodes: list of node names that will be setup by pytest xdist
        :param bool http_proxy: if False do not start the HTTP proxy
        :param bool stdout: if True stream all subprocesses stdout to standard stdout
        :param str dns_server: if set, Pebble will use it to resolve domains
        :param int http_01_port: port to use for http-01 validation; currently
            only supported for pebble without an HTTP proxy
        """
        self._construct_acme_xdist(nodes)

        self._proxy = http_proxy
        self._workspace = tempfile.mkdtemp()
        self._processes: list[subprocess.Popen[bytes]] = []
        self._stdout = sys.stdout if stdout else open(os.devnull, 'w') # pylint: disable=consider-using-with
        self._dns_server = dns_server
        self._http_01_port = DEFAULT_HTTP_01_PORT
        if http_01_port:
            if self._proxy:
                raise ValueError('Setting http_01_port is not currently supported when '
                                 'using the HTTP proxy')
            self._http_01_port = http_01_port

    def start(self) -> None:
        """Start the test stack"""
        try:
            if self._proxy:
                self._prepare_http_proxy()
            self._prepare_pebble_server()
        except BaseException as e:
            self.stop()
            raise e

    def stop(self) -> None:
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
                process.wait(MAX_SUBPROCESS_WAIT)
        finally:
            if os.path.exists(self._workspace):
                shutil.rmtree(self._workspace)
        if self._stdout != sys.stdout:
            self._stdout.close()
        print('=> Test infrastructure stopped and cleaned up.')

    def __enter__(self) -> dict[str, Any]:
        self.start()
        return self.acme_xdist

    def __exit__(self, exc_type: Optional[type[BaseException]], exc: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> None:
        self.stop()

    def _construct_acme_xdist(self, nodes: list[str]) -> None:
        """Generate and return the acme_xdist dict"""
        acme_xdist: dict[str, Any] = {}

        # Directory and ACME port are set implicitly in the docker-compose.yml
        # files of Pebble.
        acme_xdist['directory_url'] = PEBBLE_DIRECTORY_URL
        acme_xdist['challtestsrv_url'] = PEBBLE_CHALLTESTSRV_URL
        acme_xdist['http_port'] = dict(zip(nodes, range(5200, 5200 + len(nodes))))
        acme_xdist['https_port'] = dict(zip(nodes, range(5100, 5100 + len(nodes))))
        acme_xdist['other_port'] = dict(zip(nodes, range(5300, 5300 + len(nodes))))

        self.acme_xdist = acme_xdist

    def _prepare_pebble_server(self) -> None:
        """Configure and launch the Pebble server"""
        print('=> Starting pebble instance deployment...')
        pebble_artifacts_rv = pebble_artifacts.fetch(self._workspace, self._http_01_port)
        pebble_path, challtestsrv_path, pebble_config_path = pebble_artifacts_rv

        # Configure Pebble at full speed (PEBBLE_VA_NOSLEEP=1) and not randomly refusing valid
        # nonce (PEBBLE_WFE_NONCEREJECT=0) to have a stable test environment.
        environ = os.environ.copy()
        environ['PEBBLE_VA_NOSLEEP'] = '1'
        environ['PEBBLE_WFE_NONCEREJECT'] = '0'
        environ['PEBBLE_AUTHZREUSE'] = '100'
        environ['PEBBLE_ALTERNATE_ROOTS'] = str(PEBBLE_ALTERNATE_ROOTS)

        if self._dns_server:
            dns_server = self._dns_server
        else:
            dns_server = '127.0.0.1:8053'
            self._launch_process(
                [challtestsrv_path, '-management', ':{0}'.format(CHALLTESTSRV_PORT),
                 '-defaultIPv6', '""', '-defaultIPv4', '127.0.0.1', '-http01', '""',
                 '-tlsalpn01', '""', '-https01', '""'])

        self._launch_process(
            [pebble_path, '-config', pebble_config_path, '-dnsserver', dns_server, '-strict'],
            env=environ)

        self._launch_process([sys.executable, pebble_ocsp_server.__file__])

        # Wait for the ACME CA server to be up.
        print('=> Waiting for pebble instance to respond...')
        misc.check_until_timeout(self.acme_xdist['directory_url'])

        print('=> Finished pebble instance deployment.')

    def _prepare_http_proxy(self) -> None:
        """Configure and launch an HTTP proxy"""
        print(f'=> Configuring the HTTP proxy on port {self._http_01_port}...')
        http_port_map = cast(dict[str, int], self.acme_xdist['http_port'])
        mapping = {r'.+\.{0}\.wtf'.format(node): 'http://127.0.0.1:{0}'.format(port)
                   for node, port in http_port_map.items()}
        command = [sys.executable, proxy.__file__, str(self._http_01_port), json.dumps(mapping)]
        self._launch_process(command)
        print('=> Finished configuring the HTTP proxy.')

    def _launch_process(self, command: list[str], cwd: str = os.getcwd(),
                        env: Optional[Mapping[str, str]] = None,
                        force_stderr: bool = False) -> subprocess.Popen[bytes]:
        """Launch silently a subprocess OS command"""
        if not env:
            env = os.environ
        stdout = sys.stderr if force_stderr else self._stdout
        # pylint: disable=consider-using-with
        process = subprocess.Popen(
            command, stdout=stdout, stderr=subprocess.STDOUT, cwd=cwd, env=env
        )
        self._processes.append(process)
        return process


def main() -> None:
    # pylint: disable=missing-function-docstring
    parser = argparse.ArgumentParser(
        description='CLI tool to start a local instance of Pebble CA server.')
    parser.add_argument('--dns-server', '-d',
                        help='specify the DNS server as `IP:PORT` to use by '
                             'Pebble; if not specified, a local mock DNS server will be used to '
                             'resolve domains to localhost.')
    parser.add_argument('--http-01-port', type=int, default=DEFAULT_HTTP_01_PORT,
                        help='specify the port to use for http-01 validation; '
                             'this is currently only supported for Pebble.')
    args = parser.parse_args()

    acme_server = ACMEServer(
        [], http_proxy=False, stdout=True, dns_server=args.dns_server,
        http_01_port=args.http_01_port,
    )

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
