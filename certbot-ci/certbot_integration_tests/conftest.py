"""
General conftest for pytest execution of all integration tests lying
in the certbot_integration tests package.
As stated by pytest documentation, conftest module is used to set on
for a directory a specific configuration using built-in pytest hooks.

See https://docs.pytest.org/en/latest/reference.html#hook-reference
"""
import os
import json
import contextlib
import sys
import tempfile
import subprocess
import errno

from certbot_integration_tests.utils import acme


def pytest_addoption(parser):
    """
    Standard pytest hook to add options to the pytest parser.
    :param parser: current pytest parser that will be used on the CLI
    """
    parser.addoption('--acme-server', default='pebble-nonstrict',
                     choices=['boulder-v1', 'boulder-v2',
                              'pebble-nonstrict', 'pebble-strict'],
                     help='select the ACME server to use (boulder-v1, boulder-v2, '
                          'pebble-nonstrict or pebble-strict), '
                          'defaulting to pebble-nonstrict')


def pytest_configure(config):
    """
    Standard pytest hook used to add a configuration logic for each node of a pytest run.
    :param config: the current pytest configuration
    """
    if not hasattr(config, 'slaveinput'):
        with _print_on_err():
            _setup_integration_tests(config)

    if not os.environ.get('CERTBOT_ACME_TYPE'):
        raise ValueError('Error, CERTBOT_ACME_TYPE environment variable is not set !')
    config.acme_xdist = _get_acme_xdist()


def _get_acme_xdist():
    """
    Get the acme server config distribution from the environment variable "CERTBOT_ACME_XDIST"
    :return: a dict of the acme server config distribution
    """
    acme_xdist = os.environ.get('CERTBOT_ACME_XDIST')
    if not acme_xdist:
        raise ValueError('Error, CERTBOT_ACME_XDIST environment variable is not set !')

    return json.loads(acme_xdist)


@contextlib.contextmanager
def _print_on_err():
    """
    With pytest-xdist, stdout is used for nodes communication, so print is uneffective.
    However, stderr is still available. This context manager transfers stdout to stderr
    for the duration of the context, allowing to display prints to the user.
    """
    old_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        yield
    finally:
        sys.stdout = old_stdout


def _setup_integration_tests(config):
    """
    Setup the environment for integration tests.
    Will:
        - check runtime compatiblity (Docker, docker-compose, Nginx)
        - create a temporary workspace and the persistent GIT repositories space
        - configure and start paralleled ACME CA servers using Docker
        - transfer ACME CA servers configurations to pytest nodes using env variables
    :param config: Configuration of the pytest master node
    """
    # Check for runtime compatibility: some tools are required to be available in PATH
    try:
        subprocess.check_output(['docker', '-v'], stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, OSError):
        raise ValueError('Error: docker is required in PATH to launch the integration tests, '
                         'but is not installed or not available for current user.')

    try:
        subprocess.check_output(['docker-compose', '-v'], stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, OSError):
        raise ValueError('Error: docker-compose is required in PATH to launch the integration tests, '
                         'but is not installed or not available for current user.')

    workers = ['master'] if not config.option.numprocesses\
        else ['gw{0}'.format(i) for i in range(config.option.numprocesses)]

    acme_server = config.option.acme_server
    # Prepare the acme config server. Data is specific to an acme type. Module
    # utils.acme_server will handle theses specifics.
    acme_config = {}
    if 'pebble' in config.option.acme_server:
        acme_config['type'] = 'pebble'
        acme_config['option'] = 'nonstrict' if 'nonstrict' in acme_server else 'strict'
    else:
        acme_config['type'] = 'boulder'
        acme_config['option'] = 'v1' if 'v1' in acme_server else 'v2'
    # By calling setup_acme_server we ensure that all necessary acme servers instances will be
    # fully started. This runtime is reflected by the acme_xdist returned.
    acme_xdist = acme.setup_acme_server(acme_config, workers)
    os.environ['CERTBOT_ACME_TYPE'] = acme_server
    os.environ['CERTBOT_ACME_XDIST'] = json.dumps(acme_xdist)
    print('ACME xdist config:\n{0}'.format(os.environ['CERTBOT_ACME_XDIST']))
