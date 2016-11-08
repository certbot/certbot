"""Script-based Authenticator."""
import logging
import os
import sys

import zope.interface

from acme import challenges

from certbot import errors
from certbot import interfaces
from certbot import hooks

from certbot.plugins import common

logger = logging.getLogger(__name__)


CHALLENGES = ["http-01", "dns-01"]


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Script authenticator

    calls user defined script to perform authentication and
    optionally cleanup.

    """

    description = "Authenticate using user provided script(s)"

    long_description = ("Authenticate using user provided script(s). " +
                        "Authenticator script has the following environment " +
                        "variables available for it: " +
                        "CERTBOT_DOMAIN - The domain being authenticated " +
                        "CERTBOT_VALIDATION - The validation string " +
                        "CERTBOT_TOKEN - Resource name part of HTTP-01 " +
                        "challenge (HTTP-01 only). " +
                        "Cleanup script has all the above, and additional " +
                        "var: CERTBOT_AUTH_OUTPUT - stdout output from the " +
                        "authenticator"
                    )

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.cleanup_script = None
        self.auth_script = None
        self.challenges = []

    @classmethod
    def add_parser_arguments(cls, add):
        add("auth", default=None, required=False,
            help="path or command for the authentication script")
        add("cleanup", default=None, required=False,
            help="path or command for the cleanup script")

    @property
    def supported_challenges(self):
        """Challenges supported by this plugin."""
        return self.challenges

    def more_info(self):  # pylint: disable=missing-docstring
        return("This authenticator enables user to perform authentication " +
               "using shell script(s).")

    def prepare(self):
        """Prepare script plugin, check challenge, scripts and register them"""
        pref_challenges = self.config.pref_challs
        for c in pref_challenges:
            if c.typ in CHALLENGES:
                self.challenges.append(c)
        if not self.challenges and len(pref_challenges):
            # Challenges requested, but not supported
            raise errors.PluginError(
                "Unfortunately script plugin doesn't yet support " +
                "the requested challenges")

        # Challenge not defined on cli, set default
        if not self.challenges:
            self.challenges.append(challenges.Challenge.TYPES["http-01"])

        if not self.conf("auth"):
            raise errors.PluginError("Parameter --script-auth is required " +
                                     "for script plugin")
        self._prepare_scripts()

    def _prepare_scripts(self):
        """Helper method for prepare, to take care of validating scripts"""
        script_path = self.conf("auth")
        cleanup_path = self.conf("cleanup")
        if self.config.validate_hooks:
            hooks.validate_hook(script_path, "script_auth")
        self.auth_script = script_path
        if cleanup_path:
            if self.config.validate_hooks:
                hooks.validate_hook(cleanup_path, "script_cleanup")
            self.cleanup_script = cleanup_path

    def get_chall_pref(self, domain):
        """Return challenge(s) we're answering to """
        # pylint: disable=unused-argument
        return self.challenges

    def perform(self, achalls):
        """Perform the authentication per challenge"""
        mapping = {"http-01": self._setup_env_http,
                   "dns-01": self._setup_env_dns}
        responses = []
        for achall in achalls:
            response, validation = achall.response_and_validation()
            # Setup env vars
            mapping[achall.typ](achall, validation)
            output = self.execute(self.auth_script)
            if output:
                self._write_auth_output(output)
            responses.append(response)
        return responses

    def _setup_env_http(self, achall, validation):
        """Write environment variables for http challenge"""
        ev = dict()
        ev["CERTBOT_TOKEN"] = achall.chall.encode("token")
        ev["CERTBOT_VALIDATION"] = validation
        ev["CERTBOT_DOMAIN"] = achall.domain
        os.environ.update(ev)

    def _setup_env_dns(self, achall, validation):
        """Write environment variables for dns challenge"""
        ev = dict()
        ev["CERTBOT_VALIDATION"] = validation
        ev["CERTBOT_DOMAIN"] = achall.domain
        os.environ.update(ev)

    def _write_auth_output(self, out):
        """Write output from auth script to env var for
        cleanup to act upon"""
        os.environ.update({"CERTBOT_AUTH_OUTPUT": out.strip()})

    def _normalize_string(self, value):
        """Return string instead of bytestring for Python3.
        Helper function for writing env vars, as os.environ needs str"""

        if isinstance(value, bytes):
            value = value.decode(sys.getdefaultencoding())
        return str(value)

    def execute(self, shell_cmd):
        """Run a script.

        :param str shell_cmd: Command to run
        :returns: `str` stdout output"""

        _, out = hooks.execute(shell_cmd)
        return self._normalize_string(out)

    def cleanup(self, achalls):  # pylint: disable=unused-argument
        """Run cleanup.sh """
        if self.cleanup_script:
            self.execute(self.cleanup_script)
