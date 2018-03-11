"""A class that performs HTTP-01 challenges for Nginx"""

import logging
import os

from acme import challenges

from certbot import errors
from certbot.plugins import common

from certbot_nginx import obj
from certbot_nginx import nginxparser


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
        self._ipv6 = None
        self._ipv6only = None

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

        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf)

        with open(self.challenge_conf, "w") as new_conf:
            nginxparser.dump(config, new_conf)

    def _default_listen_addresses(self):
        """Finds addresses for a challenge block to listen on.
        :returns: list of :class:`certbot_nginx.obj.Addr` to apply
        :rtype: list
        """
        addresses = []
        default_addr = "%s" % self.configurator.config.http01_port
        ipv6_addr = "[::]:{0}".format(
            self.configurator.config.http01_port)
        port = self.configurator.config.http01_port

        if self._ipv6 is None or self._ipv6only is None:
            self._ipv6, self._ipv6only = self.configurator.ipv6_info(port)
        ipv6, ipv6only = self._ipv6, self._ipv6only

        if ipv6:
            # If IPv6 is active in Nginx configuration
            if not ipv6only:
                # If ipv6only=on is not already present in the config
                ipv6_addr = ipv6_addr + " ipv6only=on"
            addresses = [obj.Addr.fromstring(default_addr),
                         obj.Addr.fromstring(ipv6_addr)]
            logger.info(("Using default addresses %s and %s for authentication."),
                        default_addr,
                        ipv6_addr)
        else:
            addresses = [obj.Addr.fromstring(default_addr)]
            logger.info("Using default address %s for authentication.",
                        default_addr)
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

        validation = achall.validation(achall.account_key)
        validation_path = self._get_validation_path(achall)

        block.extend([['server_name', ' ', achall.domain],
                      ['root', ' ', document_root],
                      [['location', ' ', '=', ' ', validation_path],
                        [['default_type', ' ', 'text/plain'],
                         ['return', ' ', '200', ' ', validation]]]])
        # TODO: do we want to return something else if they otherwise access this block?
        return [['server'], block]

    def _make_or_mod_server_block(self, achall):
        """Modifies a server block to respond to a challenge.

        :param achall: Annotated HTTP-01 challenge
        :type achall:
            :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        """
        try:
            vhosts = self.configurator.choose_redirect_vhosts(achall.domain,
                '%i' % self.configurator.config.http01_port, create_if_no_match=True)
        except errors.MisconfigurationError:
            # Couldn't find either a matching name+port server block
            # or a port+default_server block, so create a dummy block
            return self._make_server_block(achall)

        # len is max 1 because Nginx doesn't authenticate wildcards
        # if len were or vhosts None, we would have errored
        vhost = vhosts[0]

        # Modify existing server block
        validation = achall.validation(achall.account_key)
        validation_path = self._get_validation_path(achall)

        location_directive = [[['location', ' ', '=', ' ', validation_path],
                               [['default_type', ' ', 'text/plain'],
                                ['return', ' ', '200', ' ', validation]]]]

        self.configurator.parser.add_server_directives(vhost,
            location_directive, replace=False)

        rewrite_directive = [['rewrite', ' ', '^(/.well-known/acme-challenge/.*)',
                                ' ', '$1', ' ', 'break']]
        self.configurator.parser.add_server_directives(vhost,
            rewrite_directive, replace=False, insert_at_top=True)
