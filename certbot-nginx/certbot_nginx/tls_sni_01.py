"""A class that performs TLS-SNI-01 challenges for Nginx"""

import logging
import os

import six

from certbot import errors
from certbot.plugins import common

from certbot_nginx import obj
from certbot_nginx import nginxparser


logger = logging.getLogger(__name__)


class NginxTlsSni01(common.TLSSNI01):
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

    def perform(self):
        """Perform a challenge on Nginx.

        :returns: list of :class:`certbot.acme.challenges.TLSSNI01Response`
        :rtype: list

        """
        if not self.achalls:
            return []

        addresses = []
        default_addr = "{0} ssl".format(
            self.configurator.config.tls_sni_01_port)

        for achall in self.achalls:
            vhosts = self.configurator.choose_vhosts(achall.domain, create_if_no_match=True)

            # len is max 1 because Nginx doesn't authenticate wildcards
            if vhosts and vhosts[0].addrs:
                addresses.append(list(vhosts[0].addrs))
            else:
                # choose_vhosts might have modified vhosts, so put this after
                ipv6, ipv6only = self.configurator.ipv6_info(
                    self.configurator.config.tls_sni_01_port)
                if ipv6:
                    # If IPv6 is active in Nginx configuration
                    ipv6_addr = "[::]:{0} ssl".format(
                        self.configurator.config.tls_sni_01_port)
                    if not ipv6only:
                        # If ipv6only=on is not already present in the config
                        ipv6_addr = ipv6_addr + " ipv6only=on"
                    addresses.append([obj.Addr.fromstring(default_addr),
                                      obj.Addr.fromstring(ipv6_addr)])
                    logger.info(("Using default addresses %s and %s for " +
                                 "TLSSNI01 authentication."),
                                default_addr,
                                ipv6_addr)
                else:
                    addresses.append([obj.Addr.fromstring(default_addr)])
                    logger.info("Using default address %s for TLSSNI01 authentication.",
                                default_addr)

        # Create challenge certs
        responses = [self._setup_challenge_cert(x) for x in self.achalls]

        # Set up the configuration
        self._mod_config(addresses)

        # Save reversible changes
        self.configurator.save("SNI Challenge", True)

        return responses

    def _mod_config(self, ll_addrs):
        """Modifies Nginx config to include challenge server blocks.

        :param list ll_addrs: list of lists of
            :class:`certbot_nginx.obj.Addr` to apply

        :raises .MisconfigurationError:
            Unable to find a suitable HTTP block in which to include
            authenticator hosts.

        """
        # Add the 'include' statement for the challenges if it doesn't exist
        # already in the main config
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
                'Certbot could not find an HTTP block to include '
                'TLS-SNI-01 challenges in %s.' % root)
        config = [self._make_server_block(pair[0], pair[1])
                  for pair in six.moves.zip(self.achalls, ll_addrs)]
        config = nginxparser.UnspacedList(config)

        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf)

        with open(self.challenge_conf, "w") as new_conf:
            nginxparser.dump(config, new_conf)

        logger.debug("Generated server block:\n%s", str(config))

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

        block = [['listen', ' ', addr.to_string(include_default=False)] for addr in addrs]

        block.extend([['server_name', ' ',
                       achall.response(achall.account_key).z_domain.decode('ascii')],
                      # access and error logs necessary for
                      # integration testing (non-root)
                      ['access_log', ' ', os.path.join(
                          self.configurator.config.work_dir, 'access.log')],
                      ['error_log', ' ', os.path.join(
                          self.configurator.config.work_dir, 'error.log')],
                      ['ssl_certificate', ' ', self.get_cert_path(achall)],
                      ['ssl_certificate_key', ' ', self.get_key_path(achall)],
                      ['include', ' ', self.configurator.mod_ssl_conf],
                      [['location', ' ', '/'], [['root', ' ', document_root]]]])
        return [['server'], block]
