"""Classes that perform challenges for Nginx"""

import logging
import os

import six

from acme import challenges

from certbot import errors
from certbot.plugins import common

from certbot_nginx import obj
from certbot_nginx import nginxparser


logger = logging.getLogger(__name__)

class NginxChallengePerformer(common.ChallengePerformer):
    """Additional helper methods for Nginx challenge performers."""

    def perform(self):
        """Perform all added challenges.

        :returns: challenge respones
        :rtype: `list` of `acme.challenges.KeyAuthorizationChallengeResponse`


        """
        raise NotImplementedError()

    def _make_server_block(self, achall, addrs):
        """Creates a server block for a challenge.

        :param achall: Annotated HTTP-01 challenge
        :type achall:
            :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        :param list addrs: addresses of challenged domain
            :class:`list` of type :class:`~nginx.obj.Addr`

        :returns: server block for the challenge host
        :rtype: list

        """
        raise NotImplementedError()

    @property
    def _challenge_conf(self):
        """Location of the challenge config file"""
        raise NotImplementedError()

    def _listen_addresses(self, default_addr, ipv6_addr, port):
        """Finds addresses for each challenge block to listen on.

        :param string default_addr: default listen directive argument for ipv4
        :param string ipv6_addr: default listen directive argument for ipv6
        :param int port: port to check for ipv6 usage

        :returns: list of lists of :class:`certbot_nginx.obj.Addr` to apply
        :rtype: list

        """
        addresses = []
        ipv6, ipv6only = self.configurator.ipv6_info(port)

        for achall in self.achalls:
            vhost = self.configurator.choose_vhost(achall.domain, create_if_no_match=True)

            if vhost is not None and vhost.addrs:
                non_ssl_addrs = (addr for addr in vhost.addrs if not addr.ssl)
                addresses.append(list(non_ssl_addrs))
            else:
                if ipv6:
                    # If IPv6 is active in Nginx configuration
                    if not ipv6only:
                        # If ipv6only=on is not already present in the config
                        ipv6_addr = ipv6_addr + " ipv6only=on"
                    addresses.append([obj.Addr.fromstring(default_addr),
                                      obj.Addr.fromstring(ipv6_addr)])
                    logger.info(("Using default addresses %s and %s for authentication."),
                                default_addr,
                                ipv6_addr)
                else:
                    addresses.append([obj.Addr.fromstring(default_addr)])
                    logger.info("Using default address %s for authentication.",
                                default_addr)
        return addresses

    def _mod_config(self, ll_addrs):
        """Modifies Nginx config to include challenge server blocks.

        :param list ll_addrs: list of lists of
            :class:`certbot_nginx.obj.Addr` to apply

        :raises .MisconfigurationError:
            Unable to find a suitable block in which to include
            authenticator hosts.

        """
        # Add the 'include' statement for the challenges if it doesn't exist
        # already in the main config
        included = False
        include_directive = ['\n', 'include', ' ', self._challenge_conf]
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
        config = [self._make_server_block(pair[0], pair[1])
                  for pair in six.moves.zip(self.achalls, ll_addrs)]
        config = nginxparser.UnspacedList(config)

        self.configurator.reverter.register_file_creation(
            True, self._challenge_conf)

        with open(self._challenge_conf, "w") as new_conf:
            nginxparser.dump(config, new_conf)

    def _make_base_block(self, addrs):
        """Creates a baseline server block that listens and logs for a challenge.

        :param list addrs: addresses of challenged domain
            :class:`list` of type :class:`~nginx.obj.Addr`

        :returns: baseline server block for the challenge host,
             without the server directive
        :rtype: list

        """
        block = [['listen', ' ', addr.to_string(include_default=False)] for addr in addrs]

        block.extend([# access and error logs necessary for
                      # integration testing (non-root)
                      ['access_log', ' ', os.path.join(
                          self.configurator.config.work_dir, 'access.log')],
                      ['error_log', ' ', os.path.join(
                          self.configurator.config.work_dir, 'error.log')]
                      ])
        return block

class NginxHttp01(NginxChallengePerformer):
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

    :param str challenge_conf: location of the challenge config file

    """

    def __init__(self, configurator):
        super(NginxHttp01, self).__init__(configurator)
        self.challenge_conf = os.path.join(
            configurator.config.config_dir, "le_http_01_cert_challenge.conf")

    @property
    def _challenge_conf(self):
        """Location of the challenge config file"""
        return self.challenge_conf

    def perform(self):
        """Perform a challenge on Nginx.

        :returns: list of :class:`certbot.acme.challenges.HTTP01Response`
        :rtype: list

        """
        if not self.achalls:
            return []

        default_addr = "%s" % self.configurator.config.http01_port
        ipv6_addr = "[::]:{0}".format(
                        self.configurator.config.http01_port)

        addresses = self._listen_addresses(default_addr, ipv6_addr,
            self.configurator.config.http01_port)

        responses = [x.response(x.account_key) for x in self.achalls]

        # Set up the configuration
        self._mod_config(addresses)

        # Save reversible changes
        self.configurator.save("HTTP Challenge", True)

        return responses

    def _get_validation_path(self, achall):
        return os.sep + os.path.join(challenges.HTTP01.URI_ROOT_PATH, achall.chall.encode("token"))

    def _make_server_block(self, achall, addrs):
        """Creates a server block for a challenge.

        :param achall: Annotated HTTP-01 challenge
        :type achall:
            :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        :param list addrs: addresses of challenged domain
            :class:`list` of type :class:`~nginx.obj.Addr`

        :returns: server block for the challenge host
        :rtype: list

        """
        block = self._make_base_block(addrs)
        validation = achall.validation(achall.account_key)
        validation_path = self._get_validation_path(achall)

        block.extend([['server_name', ' ', achall.domain],
                      [['location', ' ', '=', ' ', validation_path],
                        [['default_type', ' ', 'text/plain'],
                         ['return', ' ', '200', ' ', validation.encode()]]]])
        return [['server'], block]


class NginxTlsSni01(common.TLSSNI01, NginxChallengePerformer):
    """TLS-SNI-01 authenticator for Nginx

    :ivar configurator: NginxConfigurator object
    :type configurator: :class:`~nginx.configurator.NginxConfigurator`

    :ivar list achalls: Annotated
        class:`~certbot.achallenges.KeyAuthorizationAnnotatedChallenge`
        challenges

    :param list indices: Meant to hold indices of challenges in a
        larger array. NginxTlsSni01 is capable of solving many challenges
        at once which causes an indexing issue within NginxConfigurator
        who must return all responses in order.  Imagine NginxConfigurator
        maintaining state about where all of the http-01 Challenges,
        TLS-SNI-01 Challenges belong in the response array.  This is an
        optional utility.

    :param str challenge_conf: location of the challenge config file

    """

    @property
    def _challenge_conf(self):
        """Location of the challenge config file"""
        return self.challenge_conf

    def perform(self):
        """Perform a challenge on Nginx.

        :returns: list of :class:`certbot.acme.challenges.TLSSNI01Response`
        :rtype: list

        """
        if not self.achalls:
            return []

        default_addr = "{0} ssl".format(
            self.configurator.config.tls_sni_01_port)
        ipv6_addr = "[::]:{0} ssl".format(
            self.configurator.config.tls_sni_01_port)
        addresses = self._listen_addresses(default_addr, ipv6_addr,
            self.configurator.config.tls_sni_01_port)

        # Create challenge certs
        responses = [self._setup_challenge_cert(x) for x in self.achalls]

        # Set up the configuration
        self._mod_config(addresses)

        # Save reversible changes
        self.configurator.save("SNI Challenge", True)

        return responses

    def _make_server_block(self, achall, addrs):
        """Creates a server block for a challenge.

        :param achall: Annotated TLS-SNI-01 challenge
        :type achall:
            :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        :param list addrs: addresses of challenged domain
            :class:`list` of type :class:`~nginx.obj.Addr`

        :returns: server block for the challenge host
        :rtype: list

        """
        document_root = os.path.join(
            self.configurator.config.work_dir, "tls_sni_01_page")

        block = self._make_base_block(addrs)

        block.extend([['server_name', ' ',
                       achall.response(achall.account_key).z_domain.decode('ascii')],
                      ['ssl_certificate', ' ', self.get_cert_path(achall)],
                      ['ssl_certificate_key', ' ', self.get_key_path(achall)],
                      ['include', ' ', self.configurator.mod_ssl_conf],
                      [['location', ' ', '/'], [['root', ' ', document_root]]]])
        return [['server'], block]
