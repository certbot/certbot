# pylint: disable=too-many-lines
"""IIS Configuration"""
import logging
import re
import socket
import subprocess
import tempfile
import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Text
from typing import Tuple
from typing import Type
from typing import Union

import OpenSSL
import pkg_resources

from acme import challenges
from acme import crypto_util as acme_crypto_util
from certbot import achallenges
from certbot import crypto_util
from certbot import errors
from certbot import util
from certbot.compat import os
from certbot.display import util as display_util
from certbot.plugins import common
from certbot_iis._internal import constants
from certbot_iis._internal import iis_http_01

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import NoEncryption

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import PrivateFormat, load_pem_private_key, pkcs12
import OpenSSL.crypto

NAME_RANK = 0
START_WILDCARD_RANK = 1
END_WILDCARD_RANK = 2
REGEX_RANK = 3
NO_SSL_MODIFIER = 4


logger = logging.getLogger(__name__)


class IISConfigurator(common.Configurator):

    description = "IIS Web Server plugin"

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None]) -> None:
        default_server_root = _determine_default_server_root()
        add("server-root", default=constants.CLI_DEFAULTS["server_root"],
            help="IIS server root directory. (default: %s)" % default_server_root)
        add("ctl", default=constants.CLI_DEFAULTS["ctl"], help="Path to the "
            "'IIS' binary, used for 'configtest' and retrieving IIS "
            "version number.")
        add("sleep-seconds", default=constants.CLI_DEFAULTS["sleep_seconds"], type=int,
            help="Number of seconds to wait for IIS configuration changes "
            "to apply when reloading.")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize an IIS Configurator.

        :param tup version: version of IIS as a tuple (1, 4, 7)
            (used mostly for unittesting)

        :param tup openssl_version: version of OpenSSL linked to IIS as a tuple (1, 4, 7)
            (used mostly for unittesting)

        """
        super().__init__(*args, **kwargs)

        logger.debug("////// INIT \\\\\\")

        # Add number of outstanding challenges
        self._chall_out = 0
        self.parser: None

        self.args = args

    # This is called in determine_authenticator and determine_installer
    def prepare(self) -> None:
        """ Verify IIS is installed """
        # if not util.exe_exists(self.conf('ctl')):
        #     raise errors.NoInstallationError(
        #         "Could not find a usable 'IIS' binary. Ensure IIS exists, "
        #         "the binary is executable, and your PATH is set correctly.")

        # self.parser = iis_parser.IISParser(self.conf('server-root'))

    
    # Entry point in main.py for installing cert
    def deploy_cert(self, domain: str, cert_path: str, key_path: str, chain_path: str,
                    fullchain_path: str) -> None:
        """Deploys certificate to specified virtual host.

        .. note:: Aborts if the vhost is missing ssl_certificate or
            ssl_certificate_key.

        .. note:: This doesn't save the config files!

        :raises errors.PluginError: When unable to deploy certificate due to
            a lack of directives or configuration

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)

        """

        folder_path = os.path.dirname(os.path.abspath(cert_path))
        logger.debug("In deploy cert")
        logger.debug("cert path :" + cert_path)
        logger.debug("key path :" + key_path)
        logger.debug("folder path :" + folder_path)
        logger.debug("current path :" + os.getcwd())

        pem_cert = load_pem_x509_certificate(open(cert_path,"rb").read())
        priv_key = load_pem_private_key(open(key_path, "rb").read(), None)

        # get fullchain cert list
        with open(chain_path, 'rb') as pem_file:
            fullchain = pem_file.read()
        full_chain_certs = []
        while True:
            try:
                cert_pem, _, fullchain = fullchain.partition(b'-----END CERTIFICATE-----\n')
                cert_pem += b'-----END CERTIFICATE-----\n'
                cert = load_pem_x509_certificate(cert_pem)
                full_chain_certs.append(cert)
            except ValueError:
                # No more certificates to extract
                break
        

        encryption = (
            PrivateFormat.PKCS12.encryption_builder().
            kdf_rounds(2000).
            key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).
            hmac_hash(hashes.SHA1()).build(b"D1g!c3rt")
        )

        pfx = serialize_key_and_certificates(None, priv_key, pem_cert, full_chain_certs, encryption)

        iis_cert_name = self.args[0].iis_cert_name
        if(iis_cert_name.startswith("*.")):
            iis_cert_name=iis_cert_name.replace("*","_")

        with open(folder_path + '\\' + iis_cert_name, "wb") as pfx_cert:
            pfx_cert.write(pfx)

        current_path = os.getcwd()
        with open(current_path + '\\iis-cert-path.txt' , "w") as cert_path:
            cert_path.write(folder_path)


    def restart(self) -> None:
        """Restarts nginx server.

        :raises .errors.MisconfigurationError: If either the reload fails.

        """
        # nginx_restart(self.conf('ctl'), self.nginx_conf, self.conf('sleep-seconds'))
        

    def config_test(self) -> None:
        """Check the configuration of IIS for errors.

        :raises .errors.MisconfigurationError: If config_test fails

        """

    def more_info(self) -> str:
        """Human-readable string to help understand the module"""
        return (
            "Configures IIS to authenticate and install HTTPS.{0}"
            "Server root: {root}{0}"
            "Version: {version}".format(
                os.linesep, root=self.parser,
                version=".".join(str(i) for i in self.version))
        )

    def save(self, title: Optional[str] = None, temporary: bool = False) -> None:
        """Saves all changes to the configuration files.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        :raises .errors.PluginError: If there was an error in
            an attempt to save the configuration, or an error creating a
            checkpoint

        """
        # save_files = set(self.parser.parsed.keys())
        # self.add_to_checkpoint(save_files, self.save_notes, temporary)
        # self.save_notes = ""

        # # Change 'ext' to something else to not override existing conf files
        # self.parser.filedump(ext='')
        # if title and not temporary:
        #     self.finalize_checkpoint(title)

    def recovery_routine(self) -> None:
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        :raises .errors.PluginError: If unable to recover the configuration

        """
        # super().recovery_routine()
        # self.new_vhost = None
        # self.parser.load()

    def revert_challenge_config(self) -> None:
        """Used to cleanup challenge configurations.

        :raises .errors.PluginError: If unable to revert the challenge config.

        """
        # self.revert_temporary_config()
        # self.new_vhost = None
        # self.parser.load()

    def rollback_checkpoints(self, rollback: int = 1) -> None:
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        :raises .errors.PluginError: If there is a problem with the input or
            the function is unable to correctly revert the configuration

        """
        # super().rollback_checkpoints(rollback)
        # self.new_vhost = None
        # self.parser.load()

    def get_chall_pref(self, unused_domain: str) -> List[Type[challenges.Challenge]]:
        """Return list of challenge preferences."""
        return [challenges.HTTP01]

    # Entry point in main.py for performing challenges
    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]:
        """Perform the configuration related challenge.

        This function currently assumes all challenges will be fulfilled.
        If this turns out not to be the case in the future. Cleanup and
        outstanding challenges will have to be designed better.

        """
        self._chall_out += len(achalls)
        responses: List[Optional[challenges.ChallengeResponse]] = [None] * len(achalls)
        http_doer = iis_http_01.IISHttp01(self)

        for i, achall in enumerate(achalls):
            # Currently also have chall_doer hold associated index of the
            # challenge. This helps to put all of the responses back together
            # when they are all complete.
            if not isinstance(achall, achallenges.KeyAuthorizationAnnotatedChallenge):
                raise errors.Error("Challenge should be an instance "
                                   "of KeyAuthorizationAnnotatedChallenge")
            http_doer.add_chall(achall, i)

        http_response = http_doer.perform()
        # Must restart in order to activate the challenges.
        # Handled here because we may be able to load up other challenge types
        # self.restart()

        # Go through all of the challenges and assign them to the proper place
        # in the responses return value. All responses must be in the same order
        # as the original challenges.
        for i, resp in enumerate(http_response):
            responses[http_doer.indices[i]] = resp

        return [response for response in responses if response]

    # called after challenges are performed
    def cleanup(self, achalls: List[achallenges.AnnotatedChallenge]) -> None:
        """Revert all challenges."""
        self._chall_out -= len(achalls)

        # If all of the challenges have been finished, clean up everything
        if self._chall_out <= 0:
            self.revert_challenge_config()
            # self.restart()

    def enhance(self, domain, enhancement, options=None):
        """Perform a configuration enhancement.

        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
            for expected options for each enhancement.

        :raises .PluginError: If Enhancement is not supported, or if
            an error occurs during the enhancement.

        """

    def supported_enhancements(self):  # type: ignore
        """Returns a `collections.Iterable` of supported enhancements.

        :returns: supported enhancements which should be a subset of
            :const:`~certbot.plugins.enhancements.ENHANCEMENTS`
        :rtype: :class:`collections.Iterable` of :class:`str`

        """
        return []
    
    def get_all_names(self):  # type: ignore
        """Returns all names that may be authenticated.

        :rtype: `collections.Iterable` of `str`

        """
        logger.debug("********inside get all names************")

def _determine_default_server_root() -> str:
    default_server_root = constants.CLI_DEFAULTS["server_root"]
    return default_server_root
