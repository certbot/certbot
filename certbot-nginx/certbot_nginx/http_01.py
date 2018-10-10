"""A class that performs HTTP-01 challenges for Nginx"""

import logging
import os

from acme import challenges

from certbot import errors
from certbot.plugins import common

from certbot_nginx import obj
from certbot_nginx import nginxparser
from acme.magic_typing import List # pylint: disable=unused-import, no-name-in-module


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
        who must return all responses in order.  Imagine NginxConfigurator
        maintaining state about where all of the http-01 Challenges,
        TLS-SNI-01 Challenges belong in the response array.  This is an
        optional utility.

    """

    def __init__(self, configurator):
        super(NginxHttp01, self).__init__(configurator)
        self.challenge_conf = os.path.join(
            configurator.config.config_dir, "le_http_01_cert_challenge.conf")

    def perform(self):
        """Perform a challenge on Nginx.

        :returns: list of :class:`certbot.acme.challenges.HTTP01Response`
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

    def _mod_config(self):
        """Modifies Nginx config to include server_names_hash_bucket_size directive
           and server challenge blocks.

        :raises .MisconfigurationError:
            Unable to find a suitable HTTP block in which to include
            authenticator hosts.
        """
        included = False
        include_directive = ['\n', 'include', ' ', self.challenge_conf]
        root = self.configurator.parser.config_root

        bucket_directive = ['\n', 'server_names_hash_bucket_size', ' ', '128']

        main = self.configurator.parser.parsed[root]
        for line in main:
            if line[0] == ['http']:
                body = line[1]
                found_bucket = False
                posn = 0
                for inner_line in body:
                    if inner_line[0] == bucket_directive[1]:
                        if int(inner_line[1]) < int(bucket_directive[3]):
                            body[posn] = bucket_directive
                        found_bucket = True
                    posn += 1
                if not found_bucket:
                    body.insert(0, bucket_directive)
                if include_directive not in body:
                    body.insert(0, include_directive)
                included = True
                break
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

        with open(self.challenge_conf, "w") as new_conf:
            nginxparser.dump(config, new_conf)

    def _default_listen_addresses(self):
        """Finds addresses for a challenge block to listen on.
        :returns: list of :class:`certbot_nginx.obj.Addr` to apply
        :rtype: list
        """
        addresses = [] # type: List[obj.Addr]

        port = self.configurator.config.http01_port
        ssl_port = self.configurator.config.tls_sni_01_port

        http_items = {}
        https_items = {}

        http_items["ipv4_addr"] = "%s" % port
        http_items["ipv6_addr"] = "[::]:{0}".format(port)
        https_items["ipv4_addr"] = '{0} ssl'.format(ssl_port)
        https_items["ipv6_addr"] = '[::]:{0} ssl'.format(ssl_port)

        http_items["ipv6"], http_items["ipv6only"] = self.configurator.ipv6_info(port)
        https_items["ipv6"], https_items["ipv6only"] = self.configurator.ipv6_info(ssl_port)

        addresses = []
        for items in (http_items, https_items):
            addresses.append(obj.Addr.fromstring(items["ipv4_addr"]))
            if items["ipv6"]:
                # If IPv6 is active in Nginx configuration
                if not items["ipv6only"]:
                    # If ipv6only=on is not already present in the config
                    items["ipv6_addr"] = items["ipv6_addr"] + " ipv6only=on"
                addresses.append(obj.Addr.fromstring(items["ipv6_addr"]))

        logger.info("Using default addresses for authentication.")
        return addresses

    def _get_validation_path(self, achall):
        return os.sep + os.path.join(challenges.HTTP01.URI_ROOT_PATH, achall.chall.encode("token"))

    def _make_server_block(self, achall):
        """Creates a server block for a challenge.
        :param achall: Annotated HTTP-01 challenge
        :type achall:
            :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`
        :param list addrs: addresses of challenged domain
            :class:`list` of type :class:`~nginx.obj.Addr`
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

        snakeoil_cert, snakeoil_key = self.configurator.get_snakeoil_paths()

        ssl_block = ([
            ['\n    ', 'ssl_certificate', ' ', snakeoil_cert],
            ['\n    ', 'ssl_certificate_key', ' ', snakeoil_key],
            ['\n    ', 'include', ' ', self.configurator.mod_ssl_conf],
            ['\n    ', 'ssl_dhparam', ' ', self.configurator.ssl_dhparams],
        ])
        block.extend(ssl_block)

        # TODO: do we want to return something else if they otherwise access this block?
        return [['server'], block]

    def _location_directive_for_achall(self, achall):
        validation = achall.validation(achall.account_key)
        validation_path = self._get_validation_path(achall)

        location_directive = [['location', ' ', '=', ' ', validation_path],
                              [['default_type', ' ', 'text/plain'],
                               ['return', ' ', '200', ' ', validation]]]
        return location_directive


    def _make_or_mod_server_block(self, achall):
        """Modifies a server block to respond to a challenge.

        :param achall: Annotated HTTP-01 challenge
        :type achall:
            :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        """
        http_vhosts, https_vhosts = self.configurator.choose_http_and_https_vhosts(achall.domain,
            '%i' % self.configurator.config.http01_port)

        vhosts = set(https_vhosts).union(http_vhosts)

        for vhost in vhosts:
            # Modify existing server block
            location_directive = [self._location_directive_for_achall(achall)]

            self.configurator.parser.add_server_directives(vhost,
                location_directive)

            rewrite_directive = [['rewrite', ' ', '^(/.well-known/acme-challenge/.*)',
                                    ' ', '$1', ' ', 'break']]
            self.configurator.parser.add_server_directives(vhost,
                rewrite_directive, insert_at_top=True)

        # if vhosts doesn't contain at least one http and one https, make our own
        if not http_vhosts or not https_vhosts:
            # Couldn't find either a matching name+port server block
            # or a port+default_server block, so create a dummy block
            return self._make_server_block(achall)
