"""Provides a common base for compatibility test configurators"""
import logging
import multiprocessing
import os

import docker

from tests.compatibility import errors
from tests.compatibility import util


logger = logging.getLogger(__name__)


class ConfiguratorTester(object):
    # pylint: disable=too-many-instance-attributes
    """A common base for compatibility test configurators"""

    _NOT_ADDED_ARGS = True

    @classmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the plugin"""
        if ConfiguratorTester._NOT_ADDED_ARGS:
            group = parser.add_argument_group('docker')
            group.add_argument(
                '--docker-url', default='unix://var/run/docker.sock',
                help='URL of the docker server')
            group.add_argument(
                '--no-remove', action='store_true',
                help='do not delete container on program exit')
            ConfiguratorTester._NOT_ADDED_ARGS = False

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        self.temp_dir = util.setup_temp_dir(args.configs)
        self.config_dir = os.path.join(self.temp_dir, util.CONFIG_DIR)
        self._configs = os.listdir(self.config_dir)

        self.args = args
        self._docker_client = docker.Client(
            base_url=self.args.docker_url, version='auto')
        self.http_port, self.https_port = util.get_two_free_ports()
        self._container_id = self._log_process = None

    def has_more_configs(self):
        """Returns true if there are more configs to test"""
        return bool(self._configs)

    def cleanup_from_tests(self):
        """Performs any necessary cleanup from running plugin tests"""
        self._docker_client.stop(self._container_id)
        self._log_process.join()
        if not self.args.no_remove:
            self._docker_client.remove_container(self._container_id)

    def get_next_config(self):
        """Returns the next config directory to be tested"""
        return self._configs.pop()

    def start_docker(self, image_name):
        """Creates and runs a Docker container with the specified image"""
        for line in self._docker_client.pull(image_name, stream=True):
            logger.debug(line)

        host_config = docker.utils.create_host_config(
            binds={
                self.config_dir : {'bind' : self.config_dir, 'mode' : 'rw'}},
            port_bindings={
                80 : ('127.0.0.1', self.http_port),
                443 : ('127.0.0.1', self.https_port)},)
        container = self._docker_client.create_container(
            image_name, ports=[80, 443], volumes=self.config_dir,
            host_config=host_config)
        if container['Warnings']:
            logger.warning(container['Warnings'])
        self._container_id = container['Id']
        self._docker_client.start(self._container_id)

        self._log_process = multiprocessing.Process(
            target=self._start_log_thread)
        self._log_process.start()

    def execute_in_docker(self, command):
        """Executes command inside the running docker image"""
        exec_id = self._docker_client.exec_create(self._container_id, command)
        output = self._docker_client.exec_start(exec_id)
        if self._docker_client.exec_inspect(exec_id)['ExitCode']:
            raise errors.Error('Docker command \'{0}\' failed'.format(command))
        return output

    def _start_log_thread(self):
        client = docker.Client(base_url=self.args.docker_url, version='auto')
        for line in client.logs(self._container_id, stream=True):
            logger.debug(line)
