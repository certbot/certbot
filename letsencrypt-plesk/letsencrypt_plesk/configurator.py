"""Plesk Configuration"""
import logging

import zope.interface

from acme import challenges

from letsencrypt import achallenges
from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt import le_util
from letsencrypt import reverter

from letsencrypt.plugins import common

from letsencrypt_plesk import challenge
from letsencrypt_plesk import api_client

logger = logging.getLogger(__name__)


class PleskConfigurator(common.Plugin):
    zope.interface.implements(interfaces.IAuthenticator, interfaces.IInstaller)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Plesk - Web Server Management Tools"

    @classmethod
    def add_parser_arguments(cls, add):
        add("key", default=None,
            help="Plesk API-RPC authentication secret key.")

    def prepare(self):
        """Prepare the authenticator/installer."""

        #TODO Set up reverter
        #self.reverter = reverter.Reverter(self.config)
        #self.reverter.recovery_routine()

        self.plesk_api_client = api_client.PleskApiClient(key=self.conf('key'))
        self.plesk_challenge = challenge.PleskChallenge(self)

    def more_info(self):
        """Human-readable string to help understand the module"""
        return "Configures Plesk to authenticate and install SSL certificate."

    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return [challenges.SimpleHTTP]

    def perform(self, achalls):
        """Perform the configuration related challenge."""
        return [self.plesk_challenge.perform(x) for x in achalls]

    def cleanup(self, achalls):
        """Revert all challenges."""
        [self.plesk_challenge.cleanup(x) for x in achalls]
        self.plesk_api_client.cleanup()
