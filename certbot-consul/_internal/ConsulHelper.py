"""
Consul Helper class
"""

from secrets import token_hex
from typing import List

from certbot import errors
from consul import Consul

class ConsulHelper:
    """Helper for interfacing with Consul

    ConsulHelper makes sure to wrap any and all Consul errors in a PluginError
    so that the certbot cli command can handle those errors appropriately.

    """
    def __init__(self, client: Consul, root: str):
        self.client = client
        self.root = root

        # Ensure that the consul backend is accessable
        self.test_consul_read_write()

    def _get_rooted_path(self, key: str) -> str:
        """Prepends the root KV path to a key, if set.

        :param str key: The key to save to in Consul's KV store.

        :returns: The key prepended with the saved root KV path.
        :rtype: str

        """
        # Make sure that we only append to the root if it is not empty.
        # This is because the consul client does not allow a leading /
        return key if self.root == '' else f'{self.root}/{key}'

    def get_keys(self, root: str) -> List[str]:
        """Fetch the available keys in the specified root

        :param str root: The root path in which to list all keys.

        :returns: A list of keys in the specified root path.
            Keys are stripped of the saved root KV path.

        :rtype: List[str]

        """
        path = self._get_rooted_path(root)

        try:
            (_, values) = self.client.kv.get(path, keys=True)

            # Strip the root from the prefix
            prefix = self._get_rooted_path('')
            values = [x[x.startswith(prefix) and len(prefix):] for x in values]

            return values
        except Exception as e:
            raise errors.PluginError(
                "Could not get keys at path '{0}': {1}".format(path, e)
            )

    def get_key(self, key: str, default=None) -> str:
        """Fetch a key's value from consul and return the default value is the key does not exist

        :param str key: The key in Consul KV to read.
        :param str default: The default value to use if the key does not exist.

        :returns: The value of the specified key in Consul's KV store.
            Returns the default value if not found.

        :rtype: str

        """
        path = self._get_rooted_path(key)

        try:
            # Get the actual value
            (_, value) = self.client.kv.get(path)

            return value['Value'] if value is not None else default
        except Exception as e:
            raise errors.PluginError(
                "Could not read key '{0}': {1}".format(path, e)
            )

    def put_key(self, key: str, content: str) -> None:
        """Put a value into consul's KV store

        :param str key: The key in Consul's KV in which to store.
        :param str content: The content to store at key location in Consul's KV store.

        :returns: Nothing
        :rtype: None

        """
        path = self._get_rooted_path(key)

        try:
            # Push the value to consul
            self.client.kv.put(path, content)
        except Exception as e:
            raise errors.PluginError(
                "Could not put key '{0}': '{1}".format(path, e)
            )

    def test_consul_read_write(self) -> None:
        """Test that the consul backend can be read from / written to at the specified root"""

        # First, we try to read the root.
        try:
            self.client.kv.get(self.root, keys=True)
        except Exception as e:
            raise errors.PluginError(
                "Consul backend does not support 'read' at root '{0}': {1}".format(self.root, e)
            )

        # Try writing to the kv a temporary file, and then remove it
        # Note: We use a random key name to help minimize collisions
        key = ".CERTBOT_TEST_CONSUL_KEY_" + token_hex(8)
        path = self._get_rooted_path(key)

        try:
            self.client.kv.put(path, "REMOVE ME")
            self.client.kv.delete(path)
        except Exception as e:
            raise errors.PluginError(
                "Consul backend does not support 'write' at root '{0}': {1}".format(self.root, e)
            )
