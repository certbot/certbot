"""A class that performs HTTP-01 challenges for Nginx"""

import logging
import os

from acme import challenges

from certbot.plugins import common


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

    def _add_bucket_directive(self):
        """Modifies Nginx config to include server_names_hash_bucket_size directive."""
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
                break

    def _mod_config(self):
        """Modifies Nginx config to handle challenges.

        """
        self._add_bucket_directive()

        for achall in self.achalls:
            self._mod_server_block(achall)

    def _get_validation_path(self, achall):
        return os.sep + os.path.join(challenges.HTTP01.URI_ROOT_PATH, achall.chall.encode("token"))

    def _mod_server_block(self, achall):
        """Modifies a server block to respond to a challenge.

        :param achall: Annotated HTTP-01 challenge
        :type achall:
            :class:`certbot.achallenges.KeyAuthorizationAnnotatedChallenge`

        """
        vhost = self.configurator.choose_redirect_vhost(achall.domain,
            '%i' % self.configurator.config.http01_port, create_if_no_match=True)
        validation = achall.validation(achall.account_key)
        validation_path = self._get_validation_path(achall)

        location_directive = [[['location', ' ', '=', ' ', validation_path],
                               [['default_type', ' ', 'text/plain'],
                                ['return', ' ', '200', ' ', validation]]]]
        log_directives = [# access and error logs necessary for
                          # integration testing (non-root)
                          ['access_log', ' ', os.path.join(
                              self.configurator.config.work_dir, 'access.log')],
                          ['error_log', ' ', os.path.join(
                              self.configurator.config.work_dir, 'error.log')]
                          ]

        self.configurator.parser.add_server_directives(vhost,
            location_directive, replace=False)
        if False: # TODO: detect if we're integration testing
            self.configurator.parser.add_server_directives(vhost,
                log_directives, replace=False)
