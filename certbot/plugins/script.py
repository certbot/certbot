"""Standalone Authenticator."""
import logging
import os

import zope.interface

from subprocess import Popen, PIPE

from acme import challenges

from certbot import errors
from certbot import interfaces

from certbot.plugins import common

logger = logging.getLogger(__name__)


# Supported challenges
CHALLENGES = {"http-01": challenges.Challenge.TYPES["http-01"],
              "dns-01": challenges.Challenge.TYPES["dns-01"]}


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Script authenticator

    calls user defined script to perform authentication.

    """

    description = "Authenticate using user provided script"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.bundle_root = "/etc/letsencrypt/script.d/"
        self.prehook_name = "pre.sh"
        self.posthook_name = "post.sh"
        self.auth_name = "authenticator.sh"
        self.config_name = "config.sh"
        self.bundle = dict({
            "prepare": None,
            "authenticate": None,
            "cleanup": None,
            "config": None})
        self.bundle_config = dict()
        self.challenge = None

    @classmethod
    def add_parser_arguments(cls, add):
        add("bundle-name", "-b", default=None, required=True,
            help="script bundle name. Bundle needs to have " +
                 "authenticator.sh but can also have prehook.sh and " +
                 "posthook.sh. Certbot looks for script bundles from " +
                 "under directory /etc/letsencrypt/hooks.d ")

    @property
    def supported_challenges(self):
        """Challenges supported by this plugin."""
        return CHALLENGES[self.challenge]

    def check_path_validity(self, bundle_name):
        """Checks that the bundle path exists and is readable

        :param str bundle_name: Name of bundle to check
        :raises errors.PluginError: If path is not valid"""

        fullpath = self.bundle_root+bundle_name
        if not os.path.exists(fullpath) and os.access(fullpath, os.R_OK):
            raise errors.PluginError("Bundle path {} doesn't exist or " +
                                     "it isn't readable by Certbot".format(
                                         self.bundle_root+bundle_name))

        # Make sure that we're not executing outside of our directory
        if not os.path.realpath(fullpath).startswith(self.bundle_root):
            raise errors.PluginError(
                "Script bundle must reside under {}".format(self.bundle_root))
        return True

    def register_pieces(self, bundle_name):
        bundle_path = self.bundle_root + bundle_name
        prehook = bundle_path+"/"+self.prehook_name
        if os.path.isfile(prehook):
            if os.access(prehook, os.X_OK):
                self.bundle['prepare'] = prehook
            else:
                logger.debug("Script bundle prehook exists, but isn't executable.")
        authenticate = bundle_path+"/"+self.auth_name
        if os.path.isfile(authenticate):
            if os.access(authenticate, os.X_OK):
                self.bundle['authenticate'] = authenticate
            else:
                logger.debug("Script bundle authenticator exists, but isn't executable")
        posthook = bundle_path+"/"+self.posthook_name
        if os.path.isfile(posthook):
            if os.access(posthook, os.X_OK):
                self.bundle['cleanup'] = posthook
            else:
                logger.debug("Script bundle posthook exists, but isn't executable")
        if os.path.isfile(bundle_path+"/"+self.config_name):
            self.bundle['config'] = bundle_path+"/"+self.config_name
            self.bundle_config = self.parse_config()
        try:
            if self.bundle_config and self.bundle_config["challenge"]:
                try:
                    #self.challenge = challenges.Challenge.TYPES[self.bundle_config["challenge"]]
                    self.challenge = self.bundle_config["challenge"]
                except KeyError:
                    raise errors.PluginError(
                        "Unknown challenge type: {}".format(
                            self.bundle_config["challenge"]))
        except KeyError:
            raise errors.PluginError("Script bundle must specify one challenge")


    def more_info(self):  # pylint: disable=missing-docstring
        return("This authenticator enables user to perform authentication " +
               "using shell script.")

    def parse_config(self):
        """Parse script bundle config"""
        bundle_config_values = ["challenge"]
        bundle_config = dict()
        for i in bundle_config_values:
            bundle_config[i] = self.get_config_value(i)
        return bundle_config

    def get_config_value(self, key):
        key = key+"="
        if self.bundle['config']:
            with open(self.bundle['config'], 'r') as fh:
                contents = fh.readlines()
            for line in contents:
                if line.lower().strip().startswith(key.lower()):
                    val = line.strip()[len(key):]
                    return val.replace('"', '').replace("'", "").strip()

    def prepare(self):  # pylint: disable=missing-docstring
        """Run bundle prehook.sh if it exists"""
        bundle_name = self.config.namespace.script_bundle_name
        if self.check_path_validity(bundle_name):
            self.bundle_name = bundle_name
        self.register_pieces(bundle_name)

    def get_chall_pref(self, domain):
        # pylint: disable=unused-argument,missing-docstring
        return [CHALLENGES[self.challenge]]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        mapping = {"http-01": self._setup_env_http,
                   "dns-01": self._setup_env_dns}
        responses = []
        for achall in achalls:
            # Handle prepare script
            # TODO: exit if erroring out
            if self.bundle["prepare"]:
                self._setup_env_prepare(achall)
                if self.bundle["prepare"]:
                    self.execute(self.bundle["prepare"])

            response, validation = achall.response_and_validation()
            # Setup env vars
            mapping[achall.typ](achall, validation)
            if self.bundle["authenticate"]:
                # Should always exist though
                self.execute(self.bundle["authenticate"])
            responses.append(response)
        return responses

    def _setup_env_prepare(self, achall):
        """Write environment variables for preparation phase"""
        ev = dict()
        ev["CERTBOT_DOMAIN"] = achall.domain
        self._write_env(ev)

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
        """Run a script bundle part.

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
        """Run post.sh """
        if self.bundle['cleanup']:
            self.execute(self.bundle['cleanup'])
