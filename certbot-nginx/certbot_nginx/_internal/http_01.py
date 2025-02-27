"""A class that performs HTTP-01 challenges for Nginx"""

import logging
from typing import Any

from typing import Optional
from typing import TYPE_CHECKING

from acme import challenges
from acme.challenges import KeyAuthorizationChallengeResponse
from certbot import errors
from certbot.achallenges import KeyAuthorizationAnnotatedChallenge
from certbot.compat import os
from certbot.plugins import common
from certbot_nginx._internal import nginxparser
from certbot_nginx._internal.obj import Addr

if TYPE_CHECKING:
    from certbot_nginx._internal.configurator import NginxConfigurator

logger = logging.getLogger(__name__)


class NginxHttp01(common.ChallengePerformer):
    """HTTP-01 authenticator for Nginx

    :ivar configurator: NginxConfigurator object
    :type configurator: :class:`~nginx.configurator.NginxConfigurator`

    :ivar list achalls: Annotated
        class:`~certbot.achallenges.KeyAuthorizationAnnotatedChallenge`
        challenges

    :param list indices: Meant to hold indices of challenges in a
        larger array. NginxHttp01 is capable of solving many challenges
        at once which causes an indexing issue within NginxConfigurator
        who must return all responses in order. Imagine
        NginxConfigurator maintaining state about where all of the
        challenges, possibly of different types, belong in the response
        array. This is an optional utility.

    """

    def __init__(self, configurator: "NginxConfigurator") -> None:
        super().__init__(configurator)
        self.configurator: "NginxConfigurator"
        self.challenge_conf = os.path.join(
            configurator.config.config_dir, "le_http_01_cert_challenge.conf")

    def perform(self) -> list[KeyAuthorizationChallengeResponse]:
        """Perform a challenge on Nginx.

        :returns: list of :class:`acme.challenges.KeyAuthorizationChallengeResponse`
        :rtype: list

        """
        if not self.achalls:
            return []

        responses = [x.response(x.account_key) for x in self.achalls]

        # Set up the configuration
        self._mod_config()

        # Save reversible changes
        self.configurator.save("HTTP Challenge", True)

        return responses

    def _mod_config(self) -> None:
        """Modifies Nginx config to include server_names_hash_bucket_size directive
           and server challenge blocks.

        :raises .MisconfigurationError:
            Unable to find a suitable HTTP block in which to include
            authenticator hosts.
        """
        included = False
        include_directive = ['\n', 'include', ' ', self.challenge_conf]
        http_path = self.configurator.parser.http_path

        bucket_directive = ['\n', 'server_names_hash_bucket_size', ' ', '128']

        main = self.configurator.parser.parsed[http_path]
        # insert include directive
        for line in main:
            if line[0] == ['http']:
                body = line[1]
                if include_directive not in body:
                    body.insert(0, include_directive)
                included = True
                break

        # insert or update the server_names_hash_bucket_size directive
        # We have several options here.
        # 1) Only check nginx.conf
        # 2) Check included files, assuming they've been included inside http already,
        #     because if they added it outside an http block their config is broken anyway
        # 3) Add metadata during parsing to note if an include happened inside the http block
        #
        # 1 causes bugs; see https://github.com/certbot/certbot/issues/5199
        # 3 would require a more extensive rewrite and probably isn't necessary anyway
        # So this code uses option 2.
        found_bucket = False
        for file_contents in self.configurator.parser.parsed.values():
            body = file_contents # already inside http in an included file
            for line in file_contents:
                if line[0] == ['http']:
                    body = line[1] # enter http because this is nginx.conf
                    break

            for posn, inner_line in enumerate(body):
                if inner_line[0] == bucket_directive[1]:
                    if int(inner_line[1]) < int(bucket_directive[3]):
                        body[posn] = bucket_directive
                    found_bucket = True
                    break

            if found_bucket:
                break

        if not found_bucket:
            for line in main:
                if line[0] == ['http']:
                    body = line[1]
                    body.insert(0, bucket_directive)
                    break

        root = self.configurator.parser.config_root
        if not included:
            raise errors.MisconfigurationError(
                'Certbot could not find a block to include '
                'challenges in %s.' % root)
        config = [self._make_or_mod_server_block(achall) for achall in self.achalls]
        config = [x for x in config if x is not None]
        config = nginxparser.UnspacedList(config)
        logger.debug("Generated server block:\n%s", str(config))

        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf)

        with open(self.challenge_conf, "w", encoding="utf-8") as new_conf:
            nginxparser.dump(config, new_conf)

    def _default_listen_addresses(self) -> list[Addr]:
        """Finds addresses for a challenge block to listen on.
        :returns: list of :class:`certbot_nginx._internal.obj.Addr` to apply
        :rtype: list
        """
        addresses: list[Addr] = []
        default_addr = "%s" % self.configurator.config.http01_port
        ipv6_addr = "[::]:{0}".format(
            self.configurator.config.http01_port)
        port = self.configurator.config.http01_port

        ipv6, ipv6only = self.configurator.ipv6_info("[::]", str(port))

        if ipv6:
            # If IPv6 is active in Nginx configuration
            if not ipv6only:
                # If ipv6only=on is not already present in the config
                ipv6_addr = ipv6_addr + " ipv6only=on"
            addresses = [Addr.fromstring(default_addr),
                         Addr.fromstring(ipv6_addr)]
            logger.debug(("Using default addresses %s and %s for authentication."),
                        default_addr,
                        ipv6_addr)
        else:
            addresses = [Addr.fromstring(default_addr)]
            logger.debug("Using default address %s for authentication.",
                        default_addr)

        return addresses

    def _get_validation_path(self, achall: KeyAuthorizationAnnotatedChallenge) -> str:
        return os.sep + os.path.join(challenges.HTTP01.URI_ROOT_PATH, achall.chall.encode("token"))

    def _make_server_block(self, achall: KeyAuthorizationAnnotatedChallenge) -> list[Any]:
        """Creates a server block for a challenge.

        :param achall: Annotated HTTP-01 challenge
        :type achall: :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        :returns: server block for the challenge host
        :rtype: list
        """
        addrs = self._default_listen_addresses()
        block = [['listen', ' ', addr.to_string(include_default=False)] for addr in addrs]

        # Ensure we 404 on any other request by setting a root
        document_root = os.path.join(
            self.configurator.config.work_dir, "http_01_nonexistent")

        block.extend([['server_name', ' ', achall.domain],
                      ['root', ' ', document_root],
                      self._location_directive_for_achall(achall)
                      ])
        # TODO: do we want to return something else if they otherwise access this block?
        return [['server'], block]

    def _location_directive_for_achall(self, achall: KeyAuthorizationAnnotatedChallenge
                                       ) -> list[Any]:
        validation = achall.validation(achall.account_key)
        validation_path = self._get_validation_path(achall)

        location_directive = [['location', ' ', '=', ' ', validation_path],
                              [['default_type', ' ', 'text/plain'],
                               ['return', ' ', '200', ' ', validation]]]
        return location_directive

    def _make_or_mod_server_block(self, achall: KeyAuthorizationAnnotatedChallenge
                                  ) -> Optional[list[Any]]:
        """Modifies server blocks to respond to a challenge. Returns a new HTTP server block
           to add to the configuration if an existing one can't be found.

        :param achall: Annotated HTTP-01 challenge
        :type achall: :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        :returns: new server block to be added, if any
        :rtype: list

        """
        http_vhosts, https_vhosts = self.configurator.choose_auth_vhosts(achall.domain)

        new_vhost: Optional[list[Any]] = None
        if not http_vhosts:
            # Couldn't find either a matching name+port server block
            # or a port+default_server block, so create a dummy block
            new_vhost = self._make_server_block(achall)

        # Modify any existing server blocks
        for vhost in set(http_vhosts + https_vhosts):
            location_directive = [self._location_directive_for_achall(achall)]

            self.configurator.parser.add_server_directives(vhost, location_directive)

            rewrite_directive = [['rewrite', ' ', '^(/.well-known/acme-challenge/.*)',
                                  ' ', '$1', ' ', 'break']]
            self.configurator.parser.add_server_directives(
                vhost, rewrite_directive, insert_at_top=True)

        return new_vhost
