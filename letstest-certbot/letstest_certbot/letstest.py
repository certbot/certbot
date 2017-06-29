"""Runs integration tests on Certbot against Boulder using Docker."""
from __future__ import print_function

import argparse
import atexit
import collections
import functools
import grp
import json
import logging
import os
import pkg_resources
import shutil
import subprocess
import sys
import tempfile


TESTDATA_PATH = os.path.abspath(pkg_resources.resource_filename(
    __name__, 'testdata'))
"""Path to Let's test's test data."""


COMPOSE_PATH = os.path.join(TESTDATA_PATH, 'docker-compose.yml')
"""Path to Let's test's docker-compose.yml."""


logger = logging.getLogger(__name__)


class Error(Exception):
    """Let's test error type."""


def main():
    """Runs integration tests."""
    config = parse_args()
    logging.basicConfig(level=config.verbose * -10)
    logging.debug('Parse args are:\n%s', config)

    verify_environment()
    boulder_compose_path = set_up_boulder()
    environ = set_up_certbot(config)

    run_tests(boulder_compose_path, environ)


def run_tests(boulder_compose_path, env):
    """Runs Certbot tests with Boulder using Docker Compose.

    :param str boulder_compose_path: path to boulder docker-compose.yml
    :param env dict: environment variables for docker-compose

    """
    test_services = start_tests(boulder_compose_path, env)
    list_services(test_services)
    print_result(test_services)


def start_tests(boulder_compose_path, env):
    """Begins running tests.

    atexit is used so Docker is properly cleaned up when the program
    exits.

    :param str boulder_compose_path: path to boulder docker-compose.yml
    :param env dict: environment variables for docker-compose

    :returns: Mapping from test service names to their containers
    :rtype: dict

    """
    os.chdir(os.path.dirname(boulder_compose_path))
    check_call(['docker-compose', '-f', boulder_compose_path,
               '-f', COMPOSE_PATH, 'up', '-d'], env=env)

    try:
        test_services = get_test_services_and_containers(boulder_compose_path,
                                                         env)
        for container in test_services.values():
            atexit.register(check_call, ['docker', 'stop', container])
        # By omitting COMPOSE_PATH, the test services aren't deleted
        atexit.register(check_call, 
                        ['docker-compose', '-f', boulder_compose_path, 'down'],
                        env=env)
    except: 
        check_call(['docker-compose', '-f',
                    boulder_compose_path, '-f', COMPOSE_PATH, 'down'], env=env)
        raise

    return test_services


def list_services(test_services):
    """Prints output about the running test services.

    :param dict test_services: map from service to container

    """
    for service, container in test_services.items():
        print('{0} running in {1}'.format(service, container))
    print()
    print('You can access logs by running `docker logs -f <container>`.\n')


def print_result(test_services):
    """Waits for tests to finish and prints the results.

    :param dict test_services: map from service to container
    
    """
    failure = False

    for service, container in test_services.items():
        exit_code = int(check_output(['docker', 'wait', container]).strip())
        if exit_code:
            print('{0} failed'.format(service))
        else:
            print('{0} passed'.format(service))

    if failure:
        raise Error('One or more test instances failed!')


def set_up_certbot(config):
    """Sets up the system environment for testing.

    The requested Certbot repo and branch is cloned to a temporary
    directory and environment variables are set in preparation for
    running tests.

    :param argparse.Namespace config: parsed command line arguments

    :returns: environment variables to use with docker-compose up
    :rtype: dict

    """
    verify_script_path(config.test_script)

    env = os.environ.copy()
    env['LETSTEST_SCRIPT'] = config.test_script
    if config.pip_extra_index_url:
        env['LETSTEST_PIP_EXTRA_INDEX_URL'] = config.pip_extra_index_url

    certbot_path = git_clone_to_temp_dir(config.repo, config.branch)
    env['CERTBOT_HOST_REPO_PATH'] = certbot_path
    env['CERTBOT_REPO_PATH'] = '/opt/certbot'

    env['LETSTEST_HOST_TESTDATA_PATH'] = TESTDATA_PATH
    env['LETSTEST_TESTDATA_PATH'] = '/opt/letstest'

    return env


def verify_script_path(test_script):
    """Validates the selected test script.

    :param str test_script: basename of test script to run

    :raises Error: if test_script is invalid

    """
    verify_exe(pkg_resources.resource_filename(
        __name__, os.path.join('testdata', 'scripts', test_script)))


def verify_exe(path):
    """Asserts that path refers to an executable.

    :param str path: path to test

    :raises Error: if path doesn't refer to an executable

    """
    if not os.path.isfile(path):
        raise Error("{0} doesn't exist!".format(path))
    if not os.access(path, os.X_OK):
        raise Error("{0} isn't executable!".format(path))


def parse_args(args=None):
    """Parse command line arguments.

    If args is not provided, it is taken from argv.

    :param list args: command line arguments to parse

    :returns: parsed command line arguments
    :rtype: argparse.Namespace

    """
    if args is None:
        args = sys.argv[1:]
    return build_parser().parse_args(args)


def build_parser():
    """Create and prepare an argparse parser.

    :returns: argparse parser ready to parse command line arguments
    :rtype: argparse.ArgumentParser

    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--branch', default='master',
                        help='Certbot git branch to use.')
    parser.add_argument('--pip-extra-index-url',
                        help='An extra URL for pip to pull packages from.')
    parser.add_argument('--repo', default='https://github.com/certbot/certbot',
                        help='Certbot git repository to use.')
    # WARNING logging level is used by default
    parser.add_argument('-v', '--verbose', action='count',
                        default=logging.WARNING / -10,
                        help='Increase verbosity of output.')
    parser.add_argument('test_script', type=os.path.basename,
                        help='Script to run in tests.')
    return parser


def verify_environment():
    """Asserts the environment will allow this script to work.

    This function tests that all command line utilities are available,
    the user's version of docker-compose is new enough, and the user has
    permission to use docker-compose.

    :raises Error: if there's a problem with the environment

    """
    for command in ('docker', 'docker-compose', 'git',):
        verify_exe_exists(command)
    verify_docker_compose_version()
    verify_permissions()


def verify_exe_exists(command):
    """Asserts command exists in the user's path

    If the command cannot be found, a helpful exception is raised.

    :param str command: command to find in the user's path

    :raises Error: if command cannot be found

    """
    try:
        which(command)
    except subprocess.CalledProcessError:
        logger.debug('Encountered from which(%s):', command, exc_info=True)
        raise Error('command {0} could not be found but '
                    'is required to run this script.'.format(command))


def verify_docker_compose_version():
    """Asserts the user's docker-compose version is new enough.

    :raises Error: if it's not new enough

    """
    version_output = check_output('docker-compose --version'.split())
    version_string = version_output.split()[2]
    if version_string.endswith(','):
        version_string = version_string[:-1]
    version = [int(part) for part in version_string.split('.')]
    logger.debug('docker-compose version is %s', version)
    if version < [1, 10, 0]:
        raise Error('docker-compose >= 1.10.0 is required to use this script')


def verify_permissions():
    """Verify we're root or part of the docker group.

    :raises Error: if we have insufficient permissions

    """
    if os.geteuid() == 0:
        return
    try:
        docker_group = grp.getgrnam('docker').gr_gid
    except KeyError:
        pass
    else:
        if docker_group in os.getgroups():
            return
    raise Error("You must run this script as root "
                "or be a member of the 'docker' group")
            
        
def which(command):
    """Returns the absolute path to the command command.

    :param str command: command to find in the user's path

    :returns: absolute path to command
    :rtype: str

    :raises subprocess.CalledProcessError: if the command isn't found

    """
    return check_output('command -v {0}'.format(command), shell=True)


def set_up_boulder():
    """Prepares boulder files in a temporary directory.

    :returns: Path to Boulder's docker-compose.yml
    :rtype: str

    """
    temp_dir = git_clone_to_temp_dir('https://github.com/letsencrypt/boulder',
                                     'master', ['--depth', '1'])
    return boulder_surgery(temp_dir)


def boulder_surgery(boulder_path):
    """Edits Boulder files in preparation for running tests.

    This function causes services in Boulder's docker-compose file to
    use the default network_mode and configures Boulder to use Docker's
    embedded DNS server rather than always resolving domains to a
    specified IP.

    :param str boulder_path: path to the local boulder repo

    :returns: path to the modified Docker Compose file
    :rtype: str

    """
    change_dns_resolvers(boulder_path)
    compose_path = os.path.join(boulder_path, 'docker-compose.yml')
    remove_network_mode(compose_path)
    return compose_path


def change_dns_resolvers(boulder_path):
    """Edits Boulder's configuration to use Docker's DNS resolver.

    :param str boulder_path: path to the local boulder repo

    """
    config_dir = os.path.join(boulder_path, 'test', 'config')
    assert os.path.isdir(config_dir), 'Missing Boulder config dir!'
    change_dns_resolver(os.path.join(config_dir, 'ra.json'))
    change_dns_resolver(os.path.join(config_dir, 'va.json'))


def change_dns_resolver(config_path):
    """Edits a Boulder configuration file to use Docker's DNS resolver.

    :param str config_path: path to the boulder config file to edit

    """
    with open(config_path) as f:
        data = json.load(f)

    data['common']['dnsResolver'] = '127.0.0.11:53'
    dumped_data = json.dumps(data)
    dumped_data += '\n'

    with open(config_path, 'w') as f:
        f.write(dumped_data)
    logger.debug('Updated %s to:\n%s', config_path, dumped_data)


def remove_network_mode(compose_path):
    """Use the default network_mode in a docker-compose file.

    Any lines changing the network_mode will be removed from the file.

    :param str compose_path: path to a Docker Compose file

    """
    with open(compose_path) as f:
        original = f.read()
    with open(compose_path, 'w') as f:
        f.writelines(line + '\n' for line in original.splitlines()
                     if not line.lstrip().startswith('network_mode'))


def get_test_services_and_containers(boulder_compose_path, env):
    """Provides a mapping from test service to Docker container.

    :param str boulder_compose_path: path to Boulder's Compose file
    :param env dict: environment variables for docker-compose

    :returns: Mapping from test service names to their containers
    :rtype: dict

    """
    return collections.OrderedDict(
        (name, get_container(boulder_compose_path, name, env))
        for name in get_test_services(boulder_compose_path, env))


def get_container(boulder_compose_path, service_name, env):
    """Returns the container for the specified service.

    :param str boulder_compose_path: path to Boulder's Compose file
    :param str service_name: Compose service to find the container of
    :param env dict: environment variables for docker-compose

    :returns: Docker container running the specified service
    :rtype: str

    """
    return check_output(
        ['docker-compose', '-f', boulder_compose_path,
        '-f', COMPOSE_PATH, 'ps', '-q', service_name], env=env).strip()


def get_test_services(boulder_compose_path, env):
    """Returns the names of Docker Compose services for testing.

    Service names are returned in sorted order.

    :param str boulder_compose_path: path to Boulder's docker-compose.yml
    :param env dict: environment variables for docker-compose
    
    :returns: Docker compose services used for testing
    :rtype: list of str

    """
    all_services = docker_compose_services(
        env, boulder_compose_path, COMPOSE_PATH)
    boulder_services = docker_compose_services(env, boulder_compose_path)
    return [service for service in sorted(all_services)
            if service not in boulder_services]


def docker_compose_services(env, *compose_files):
    """Determines the list of services from a Docker Compose setup.

    Files are passed to docker-compose in the same order they are given
    compose_files.

    :param env dict: environment variables for docker-compose
    :param list compose_files: paths to Docker compose files

    :returns: list of service names
    :rtype: list of str

    """
    assert compose_files, 'At least one compose file is required!'

    cmd = ['docker-compose']
    for f in compose_files:
        cmd.append('-f')
        cmd.append(f)
    cmd.extend(('config', '--services',))

    services = check_output(cmd, env=env).splitlines()
    logger.debug('Services found in %s are %s', compose_files, services)
    return services


def git_clone_to_temp_dir(repo, branch, extra_args=None):
    """Clones the specified repo and branch into a temporary directory.

    This function ensures the temporary directory is deleted when this
    script exits.

    :param str repo: git repository to clone
    :param str branch: branch of repo to clone
    :param list extra_args: additional arguments to git clone

    :returns: temporary directory containing the cloned contents
    :rtype: str

    """
    temp_dir = tempfile.mkdtemp()
    atexit.register(
        functools.partial(shutil.rmtree, temp_dir, ignore_errors=True))

    args = ['git', 'clone', '--branch', branch]
    if extra_args:
        args += extra_args
    args += [repo, temp_dir]
    check_call(args)
    return temp_dir


def check_call(args, shell=False, env=None):
    """subprocess.check_call with logging.

    :param args: command to run with subprocess
    :type args: list or str
    :param bool shell: whether the command should be executed in a shell
    :param dict env: environment variables to use

    :raises subprocess.CalledProcessError: if the command fails

    """
    check_output(args, shell, env)


def check_output(args, shell=False, env=None):
    """subprocess.check_output with logging.

    :param args: command to run with subprocess
    :type args: list or str
    :param bool shell: whether the command should be executed in a shell
    :param dict env: environment variables to use

    :returns: stdout output
    :rtype: str

    :raises subprocess.CalledProcessError: if the command fails

    """
    logger.debug('Calling %s', args)
    process = subprocess.Popen(args, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=shell, env=env,
                               universal_newlines=True)

    stdout, stderr = process.communicate()
    if stdout:
        logger.debug('stdout was:\n%s', stdout)
    if stderr:
        logger.debug('stderr was:\n%s', stderr)
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, args)
    return stdout


if __name__ == '__main__':
    main()
