"""Provides a common base for configurator proxies"""
import logging
import os
import shutil
import tempfile

import docker

from certbot import constants
from certbot_compatibility_test import errors
from certbot_compatibility_test import util


logger = logging.getLogger(__name__)


class Proxy(object):
    # pylint: disable=too-many-instance-attributes
    """A common base for compatibility test configurators"""

    _NOT_ADDED_ARGS = True

    @classmethod
    def add_parser_arguments(cls, parser):
        """Adds command line arguments needed by the plugin"""
        if Proxy._NOT_ADDED_ARGS:
            group = parser.add_argument_group("docker")
            group.add_argument(
                "--docker-url", default="unix://var/run/docker.sock",
                help="URL of the docker server")
            group.add_argument(
                "--no-remove", action="store_true",
                help="do not delete container on program exit")
            Proxy._NOT_ADDED_ARGS = False

    def __init__(self, args):
        """Initializes the plugin with the given command line args"""
        self._temp_dir = tempfile.mkdtemp()
        self.le_config = util.create_le_config(self._temp_dir)
        config_dir = util.extract_configs(args.configs, self._temp_dir)
        self._configs = [
            os.path.join(config_dir, config)
            for config in os.listdir(config_dir)]

        self.args = args
        self._docker_client = docker.Client(
            base_url=self.args.docker_url, version="auto")
        self.http_port, self.https_port = util.get_two_free_ports()
        self._container_id = None

    def has_more_configs(self):
        """Returns true if there are more configs to test"""
        return bool(self._configs)

    def cleanup_from_tests(self):
        """Performs any necessary cleanup from running plugin tests"""
        self._docker_client.stop(self._container_id, 0)
        if not self.args.no_remove:
            self._docker_client.remove_container(self._container_id)

    def load_config(self):
        """Returns the next config directory to be tested"""
        shutil.rmtree(self.le_config.work_dir, ignore_errors=True)
        backup = os.path.join(self.le_config.work_dir, constants.BACKUP_DIR)
        os.makedirs(backup)
        return self._configs.pop()

    def start_docker(self, image_name, command):
        """Creates and runs a Docker container with the specified image"""
        logger.warning("Pulling Docker image. This may take a minute.")
        for line in self._docker_client.pull(image_name, stream=True):
            logger.debug(line)

        host_config = docker.utils.create_host_config(
            binds={self._temp_dir: {"bind": self._temp_dir, "mode": "rw"}},
            port_bindings={
                80: ("127.0.0.1", self.http_port),
                443: ("127.0.0.1", self.https_port)},)
        container = self._docker_client.create_container(
            image_name, command, ports=[80, 443], volumes=self._temp_dir,
            host_config=host_config)
        if container["Warnings"]:
            logger.warning(container["Warnings"])
        self._container_id = container["Id"]
        self._docker_client.start(self._container_id)

    def check_call(self, command, *args, **kwargs):
        # pylint: disable=unused-argument
        """Simulates a call to check_call but executes the command in the
        running docker image

        """
        if self.popen(command).returncode:
            raise errors.Error(
                "{0} exited with a nonzero value".format(command))

    def popen(self, command, *args, **kwargs):
        # pylint: disable=unused-argument
        """Simulates a call to Popen but executes the command in the
        running docker image

        """
        class SimplePopen(object):
            # pylint: disable=too-few-public-methods
            """Simplified Popen object"""
            def __init__(self, returncode, output):
                self.returncode = returncode
                self._stdout = output
                self._stderr = output

            def communicate(self):
                """Returns stdout and stderr"""
                return self._stdout, self._stderr

        if isinstance(command, list):
            command = " ".join(command)

        returncode, output = self.execute_in_docker(command)
        return SimplePopen(returncode, output)

    def execute_in_docker(self, command):
        """Executes command inside the running docker image"""
        logger.debug("Executing '%s'", command)
        exec_id = self._docker_client.exec_create(self._container_id, command)
        output = self._docker_client.exec_start(exec_id)
        returncode = self._docker_client.exec_inspect(exec_id)["ExitCode"]
        return returncode, output

    def copy_certs_and_keys(self, cert_path, key_path, chain_path=None):
        """Copies certs and keys into the temporary directory"""
        cert_and_key_dir = os.path.join(self._temp_dir, "certs_and_keys")
        if not os.path.isdir(cert_and_key_dir):
            os.mkdir(cert_and_key_dir)

        cert = os.path.join(cert_and_key_dir, "cert")
        shutil.copy(cert_path, cert)
        key = os.path.join(cert_and_key_dir, "key")
        shutil.copy(key_path, key)
        if chain_path:
            chain = os.path.join(cert_and_key_dir, "chain")
            shutil.copy(chain_path, chain)
        else:
            chain = None

        return cert, key, chain
