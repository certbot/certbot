"""
General conftest for pytest execution of all integration tests lying
in the certbot_integration tests package.
As stated by pytest documentation, conftest module is used to set on
for a directory a specific configuration using built-in pytest hooks.

See https://docs.pytest.org/en/latest/reference.html#hook-reference
"""
from __future__ import print_function
import contextlib
import subprocess
import sys

from certbot_integration_tests.utils import acme_server as acme_lib


def pytest_addoption(parser):
    """
    Standard pytest hook to add options to the pytest parser.
    :param parser: current pytest parser that will be used on the CLI
    """
    parser.addoption('--acme-server', default='pebble',
                     choices=['boulder-v1', 'boulder-v2', 'pebble'],
                     help='select the ACME server to use (boulder-v1, boulder-v2, '
                          'pebble), defaulting to pebble')


def pytest_configure(config):
    """
    Standard pytest hook used to add a configuration logic for each node of a pytest run.
    :param config: the current pytest configuration
    """
    if not hasattr(config, 'slaveinput'):  # If true, this is the primary node
        with _print_on_err():
            config.acme_xdist = _setup_primary_node(config)


def pytest_configure_node(node):
    """
    Standard pytest-xdist hook used to configure a worker node.
    :param node: current worker node
    """
    node.slaveinput['acme_xdist'] = node.config.acme_xdist


@contextlib.contextmanager
def _print_on_err():
    """
    During pytest-xdist setup, stdout is used for nodes communication, so print is useless.
    However, stderr is still available. This context manager transfers stdout to stderr
    for the duration of the context, allowing to display prints to the user.
    """
    old_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = old_stdout


def _setup_primary_node(config):
    """
    Setup the environment for integration tests.
    Will:
        - check runtime compatibility (Docker, docker-compose, Nginx)
        - create a temporary workspace and the persistent GIT repositories space
        - configure and start paralleled ACME CA servers using Docker
        - transfer ACME CA servers configurations to pytest nodes using env variables
    :param config: Configuration of the pytest primary node
    """
    # Check for runtime compatibility: some tools are required to be available in PATH
    if 'boulder' in config.option.acme_server:
        try:
            subprocess.check_output(['docker', '-v'], stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, OSError):
            raise ValueError('Error: docker is required in PATH to launch the integration tests on'
                             'boulder, but is not installed or not available for current user.')

        try:
            subprocess.check_output(['docker-compose', '-v'], stderr=subprocess.STDOUT)
        except (subprocess.CalledProcessError, OSError):
            raise ValueError('Error: docker-compose is required in PATH to launch the integration tests, '
                             'but is not installed or not available for current user.')

    # Parameter numprocesses is added to option by pytest-xdist
    workers = ['primary'] if not config.option.numprocesses\
        else ['gw{0}'.format(i) for i in range(config.option.numprocesses)]

    # By calling setup_acme_server we ensure that all necessary acme server instances will be
    # fully started. This runtime is reflected by the acme_xdist returned.
    acme_server = acme_lib.ACMEServer(config.option.acme_server, workers)
    config.add_cleanup(acme_server.stop)
    print('ACME xdist config:\n{0}'.format(acme_server.acme_xdist))
    acme_server.start()

    return acme_server.acme_xdist
