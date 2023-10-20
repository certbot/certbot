"""A class that performs HTTP-01 challenges for IIS"""

import logging
from typing import List
from typing import TYPE_CHECKING

from acme.challenges import KeyAuthorizationChallengeResponse
from certbot import util
from certbot.compat import os
from certbot.plugins import common

if TYPE_CHECKING:
    from certbot_iis._internal.configurator import IISConfigurator

logger = logging.getLogger(__name__)


class IISHttp01(common.ChallengePerformer):
    """HTTP-01 authenticator for IIS"""

    def __init__(self, configurator) -> None:
        super().__init__(configurator)
        # self.configurator: "IISConfigurator"
        self.challenge_conf = util.escape_char_conv(os.path.join(
            configurator.config.config_dir, "le_http_01_cert_challenge.conf"))

    def perform(self) -> List[KeyAuthorizationChallengeResponse]:
        """Perform a challenge on IIS   .

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
        logger.debug("*****************challanges performed****************")
