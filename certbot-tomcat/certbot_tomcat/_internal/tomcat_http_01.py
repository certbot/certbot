"""A class that performs HTTP-01 challenges for Tomcat"""

import logging

from acme import challenges
from typing  import List
from certbot import errors
from certbot.compat import os
from certbot.plugins import common
from certbot_nginx._internal import nginxparser
from certbot_nginx._internal import obj

logger = logging.getLogger(__name__)


class TomcatHttp01(common.ChallengePerformer):
    """HTTP-01 authenticator for Tomcat"""

    def __init__(self, configurator):
        super(TomcatHttp01, self).__init__(configurator)
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
        logger.debug("*****************challanges performed****************")