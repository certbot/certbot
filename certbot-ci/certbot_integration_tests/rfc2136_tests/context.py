import os
import pkg_resources
from shutil import rmtree, copytree
import socket
import subprocess
import time

from certbot_integration_tests.certbot_tests import context as certbot_context
from certbot_integration_tests.utils import certbot_call


BIND_DOCKER_IMAGE = 'internetsystemsconsortium/bind9:9.16'
BIND_BIND_ADDRESS = ('127.0.0.1', 45953)

# A DNS message which is a query for '. IN A' transaction ID 0xe785. This is used by
# _wait_until_ready to check that BIND is responding without depending on dnspython.
BIND_TEST_QUERY = bytearray.fromhex('0028e7850120000100000000000100000100010000'
                                    '29100000000000000c000a00083ad084e525a28702')


class IntegrationTestsContext(certbot_context.IntegrationTestsContext):
    """Integration test context for certbot-dns-rfc2136"""
    def __init__(self, request):
        super(IntegrationTestsContext, self).__init__(request)

        # Provision config dirs in the workspace for BIND
        self.bind_root = os.path.join(self.workspace, 'bind')
        os.mkdir(self.bind_root)

        # Copy the premade BIND configuration into the workspace
        bind_conf_src = pkg_resources.resource_filename(
          'certbot_integration_tests', 'assets/bind-config')
        for dir in ['conf', 'zones']:
          dst = os.path.join(self.bind_root, dir)
          copytree(os.path.join(bind_conf_src, dir), dst)

        # Bring up the BIND container against the workspace
        self._start_bind()

    def cleanup(self):
        self._stop_bind()
        super(IntegrationTestsContext, self).cleanup()

    def certbot_test_rfc2136(self, args):
        """
        Main command to execute certbot using the RFC2136 DNS authenticator.
        :param list args: list of arguments to pass to Certbot
        """
        command = ['--authenticator', 'dns-rfc2136', '--dns-rfc2136-propagation-seconds', '5']
        command.extend(args)
        return certbot_call.certbot_test(
            command, self.directory_url, self.http_01_port, self.tls_alpn_01_port,
            self.config_dir, self.workspace, force_renew=True)

    def _start_bind(self):
        addr_str = '{}:{}'.format(BIND_BIND_ADDRESS[0], BIND_BIND_ADDRESS[1])
        self.process = subprocess.Popen([
          'docker', 'run', '--rm',
          '-p', '{}:53/udp'.format(addr_str),
          '-p', '{}:53/tcp'.format(addr_str),
          '-v', '{}/conf:/etc/bind'.format(self.bind_root),
          '-v', '{}/zones:/var/lib/bind'.format(self.bind_root),
          BIND_DOCKER_IMAGE
        ])

        assert self.process.poll() is None

        try:
          self._wait_until_ready()
        except:
          # The container might be running even if we think it isn't
          self._stop_bind()
          raise

    def _stop_bind(self):
        assert self.process.poll() is None
        self.process.terminate()
        self.process.wait()
        rmtree(self.bind_root)

    def _wait_until_ready(self, attempts=30):
      # type: (int) -> None
      """
      Polls the DNS server over TCP until it gets a response, or until
      it runs out of attempts and raises a ValueError.
      The DNS response message must match the txn_id of the DNS query message,
      but otherwise the contents are ignored.
      :param int attempts: The number of attempts to make.
      """
      for _ in range(attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
          sock.connect(BIND_BIND_ADDRESS)
          sock.sendall(BIND_TEST_QUERY)
          buf = sock.recv(1024)
          # We should receive a DNS message with the same tx_id
          if buf and len(buf) > 4 and buf[2:4] == BIND_TEST_QUERY[2:4]:
            return
          # If we got a response but it wasn't the one we wanted, wait a little
          time.sleep(1)
        except:
          # If there was a network error, wait a little
          time.sleep(1)
          pass
        finally:
          sock.close()

      raise ValueError(
        'Gave up waiting for DNS server {} to respond'.format(BIND_BIND_ADDRESS))

