"""Consul Certbot Plugins

Stores certificates into a Consul KV store for use in cluster applications.

"""
import consul
from functools import reduce
from typing import Callable, Iterable, List, Optional, Set, Union

from certbot import errors, interfaces
from certbot import util
from certbot.plugins import common

from _internal import constants
from _internal.CertMapping import CertMapping, CertType
from _internal.ConsulHelper import ConsulHelper

class Installer(common.Plugin, interfaces.Installer):
    """Installer using the Consul KV store."""

    description = "Install certificates to a Consul KV store."

    # Class properties
    _consul_helper: ConsulHelper

    # Cert info
    _mappings: List[CertMapping] = []

    #######################
    # Plugin overrides
    #######################
    @classmethod
    def add_parser_arguments(cls, add: Callable):
        add(
            constants.ARG_MAPPING,
            action = "append",
            type = str,
            help = "Mapping between consul key and cert components." +
                "(Ex. test.example.com:fullchain,privkey)",
        )
        add(
            constants.ARG_KV_ROOT,
            default = constants.ARG_KV_ROOT_DEFAULT,
            type = str,
            help = "The root path in conul's KV store in which to save the certificates.",
        )
        add(
            constants.ARG_NO_VERIFY_SSL,
            default = constants.ARG_NO_VERIFY_SSL_DEFAULT,
            action = "store_true",
            help="Skip SSL verification when communicating with consul.",
        )
        add(
            constants.ARG_DATA_CENTER,
            default = constants.ARG_DATA_CENTER_DEFAULT,
            type = str,
            help="The consul data center.",
        )

    def more_info(self) -> str:
        """Human-readable string to help understand the module"""

        return (
            "Save certificates to a Consul KV store."
        )

    def prepare(self) -> None:
        """Prepare the plugin

        Checks the existance of the consul server and that the KV is present.
        Needed environment variables are the same as those needed by consul:
        - CONSUL_HTTP_ADDR: The HTTP address (with the protocol and port)
        - CONSUL_HTTP_TOKEN: The token (if needed) with the relevant ACL permissions

        This also creates a key containing the metadata for the certs installed by this tool.

        """

        # Fetch configuration options
        dc = self.conf(constants.ARG_DATA_CENTER)
        verify = not self.conf(constants.ARG_NO_VERIFY_SSL)
        root = self.conf(constants.ARG_KV_ROOT)

        # Create our consul client
        client = consul.Consul(
            dc=dc,
            verify=verify,
        )

        # Construct our consul helper.
        # Note: This will raise an exception on error due to missing permissions
        self._consul_helper = ConsulHelper(client, root)

        # Make sure that we have valid mappings
        self._mappings = [
            CertMapping(key = x.split(':')[0], contents = x.split(':')[1].split(','))
            for x in self.conf("mapping")
        ]

        if self._mappings is None or len(self._mappings) == 0:
            raise errors.PluginError("No valid mappings found! Specify them with --consul-mappings")

    #######################
    # Installer Overrides
    #######################
    def get_all_names(self) -> Iterable[str]:
        """Returns all names found in the Consul KV store.

        :returns: All ServerNames, ServerAliases, and reverse DNS entries for
                  virtual host addresses
        :rtype: set

        """
        # Fetch the names of all of the files from consul
        all_names: Set[str] = set(self._consul_helper.get_keys(''))

        return util.get_filtered_names(all_names)

    def deploy_cert(
        self, domain: str, cert_path: str, key_path: str,
        chain_path: str, fullchain_path: str
    ) -> None:
        """Deploy a cert to Consul's KV store."""

        # Find the corresponding mapping corresponding to the domain
        mapping = [x for x in self._mappings if x.key == domain]

        # Make sure that there is a mapping and that it is unique
        if len(mapping) == 0:
            raise errors.PluginError(f"No mapping found for domain: {domain}")
        elif len(mapping) > 1:
            raise errors.PluginError(f"Multiple mappings found for the same domain: {domain}")

        # Get the files needed for the mappings
        mapping_to_file = {
            CertType.CHAIN.value: chain_path,
            CertType.FULL_CHAIN.value: fullchain_path,
            CertType.PRIVATE_KEY.value: key_path,
            CertType.CERTIFICATE.value: cert_path,
        }
        files = [mapping_to_file[x] for x in mapping[0].contents]

        # Read in the files into the overall content
        def file_reducer(acc: str, next_file: str):
            result = acc
            with open(next_file, 'r') as file:
                result += '\n' + file.read()

            return result

        content = reduce(file_reducer, files, "")

        # Save the mapped content into consul
        # Note: This will raise any error from consul
        self._consul_helper.put_key(domain, content)

    # Disabled overrides below
    def supported_enhancements(self) -> List[str]:
        return []
    def enhance(
        self, domain: str, enhancement: str,
        options: Optional[Union[List[str], str]] = None
    ) -> None:
        pass
    def rollback_checkpoints(self, rollback: int = 1) -> None:
        pass
    def restart(self) -> None:
        pass
    def config_test(self) -> None:
        pass
    def recovery_routine(self) -> None:
        pass
    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        pass
