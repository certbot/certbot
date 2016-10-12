"""Standalone Authenticator."""
import logging
import os

import zope.interface

from subprocess import Popen, PIPE

from certbot import errors
from certbot import interfaces

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

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.cleanup_script = None
        self.auth_script = None
        self.challenges = []

    @classmethod
    def add_parser_arguments(cls, add):
        add("auth", default=None, required=True,
            help="path to the authentication script")
        add("cleanup", default=None, required=False,
            help="path to the cleanup script")

    @property
    def supported_challenges(self):
        """Challenges supported by this plugin."""
        return self.challenges

    def check_script_validity(self, script_path):
        """Checks that the script exists and is executable

        :param str script_path: Path of script to check
        :raises errors.PluginError: If script is not valid
        :returns `boolean`: If script is valid"""

        if os.path.exists(script_path) and os.path.isfile(script_path):
            if os.access(script_path, os.X_OK):
                return True
            else:
                raise errors.PluginError(
                    "Script {} isn't readable by Certbot".format(script_path))
        else:
            raise errors.PluginError(
                "Script {} does not exist".format(script_path))

        return False

    def more_info(self):  # pylint: disable=missing-docstring
        return("This authenticator enables user to perform authentication " +
               "using shell script(s).")

    def prepare(self):
        """Prepare script plugin, check challenge, scripts and register them"""
        try:
            challenges = self.config.namespace.pref_challs
            for c in challenges:
                if c.typ in CHALLENGES:
                    self.challenges.append(c)
            if not self.challenges and len(challenges):
                # Challenges requested, but not supported
                raise errors.PluginError(
                    "Unfortunately script plugin doesn't yet support " +
                    "the requested challenges")

        except AttributeError:
            # Challenge not defined on cli, we have default set in __init__
            pass

        script_path = self.config.namespace.script_auth
        cleanup_path = self.config.namespace.script_cleanup
        if self.check_script_validity(script_path):
            self.auth_script = script_path
        if cleanup_path and self.check_script_validity(cleanup_path):
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
            self.execute(self.auth_script)
            responses.append(response)
        return responses

    def _setup_env_http(self, achall, validation):
        """Write environment variables for http challenge"""
        ev = dict()
        ev["CERTBOT_TOKEN"] = achall.chall.encode("token")
        ev["CERTBOT_VALIDATION"] = validation
        ev["CERTBOT_DOMAIN"] = achall.domain
        self._write_env(ev)

    def _setup_env_dns(self, achall, validation):
        """Write environment variables for dns challenge"""

        ev = dict()
        ev["CERTBOT_VALIDATION"] = validation
        ev["CERTBOT_DOMAIN"] = achall.domain
        self._write_env(ev)

    def _write_env(self, env_vars):
        """Write environment variables"""
        for k in env_vars.keys():
            os.environ[k] = env_vars[k]

    def execute(self, shell_cmd):
        """Run a script.

        :param str shell_cmd: Command to run
        :returns: `tuple` (`int` returncode, `str` stderr"""
        cmd = Popen(shell_cmd, shell=True, stdout=PIPE, stderr=PIPE,
                    stdin=PIPE)
        _out, err = cmd.communicate()
        if cmd.returncode != 0:
            logger.error('Command "%s" returned error code %d',
                         shell_cmd, cmd.returncode)
        if err:
            logger.error('Error output from %s:\n%s', shell_cmd, err)

        return (cmd.returncode, err)

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        """Run cleanup.sh """
        if self.cleanup_script:
            self.execute(self.cleanup_script)
