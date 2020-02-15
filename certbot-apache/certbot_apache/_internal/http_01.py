"""A class that performs HTTP-01 challenges for Apache"""
import logging

from acme.magic_typing import List
from acme.magic_typing import Set
from certbot import errors
from certbot.compat import filesystem
from certbot.compat import os
from certbot.plugins import common
from certbot_apache._internal.obj import VirtualHost  # pylint: disable=unused-import
from certbot_apache._internal.parser import get_aug_path

logger = logging.getLogger(__name__)


class ApacheHttp01(common.ChallengePerformer):
    """Class that performs HTTP-01 challenges within the Apache configurator."""

    CONFIG_TEMPLATE22_PRE = """\
        RewriteEngine on
        RewriteRule ^/\\.well-known/acme-challenge/([A-Za-z0-9-_=]+)$ {0}/$1 [L]

    """
    CONFIG_TEMPLATE22_POST = """\
        <Directory {0}>
            Order Allow,Deny
            Allow from all
        </Directory>
        <Location /.well-known/acme-challenge>
            Order Allow,Deny
            Allow from all
        </Location>
    """

    CONFIG_TEMPLATE24_PRE = """\
        RewriteEngine on
        RewriteRule ^/\\.well-known/acme-challenge/([A-Za-z0-9-_=]+)$ {0}/$1 [END]
    """
    CONFIG_TEMPLATE24_POST = """\
        <Directory {0}>
            Require all granted
        </Directory>
        <Location /.well-known/acme-challenge>
            Require all granted
        </Location>
    """

    def __init__(self, *args, **kwargs):
        super(ApacheHttp01, self).__init__(*args, **kwargs)
        self.challenge_conf_pre = os.path.join(
            self.configurator.conf("challenge-location"),
            "le_http_01_challenge_pre.conf")
        self.challenge_conf_post = os.path.join(
            self.configurator.conf("challenge-location"),
            "le_http_01_challenge_post.conf")
        self.challenge_dir = os.path.join(
            self.configurator.config.work_dir,
            "http_challenges")
        self.moded_vhosts = set()  # type: Set[VirtualHost]

    def perform(self):
        """Perform all HTTP-01 challenges."""
        if not self.achalls:
            return []
        # Save any changes to the configuration as a precaution
        # About to make temporary changes to the config
        self.configurator.save("Changes before challenge setup", True)

        self.configurator.ensure_listen(str(
            self.configurator.config.http01_port))
        self.prepare_http01_modules()

        responses = self._set_up_challenges()

        self._mod_config()
        # Save reversible changes
        self.configurator.save("HTTP Challenge", True)

        return responses

    def prepare_http01_modules(self):
        """Make sure that we have the needed modules available for http01"""

        if self.configurator.conf("handle-modules"):
            needed_modules = ["rewrite"]
            if self.configurator.version < (2, 4):
                needed_modules.append("authz_host")
            else:
                needed_modules.append("authz_core")
            for mod in needed_modules:
                if mod + "_module" not in self.configurator.parser.modules:
                    self.configurator.enable_mod(mod, temp=True)

    def _mod_config(self):
        selected_vhosts = []  # type: List[VirtualHost]
        http_port = str(self.configurator.config.http01_port)
        for chall in self.achalls:
            # Search for matching VirtualHosts
            for vh in self._matching_vhosts(chall.domain):
                selected_vhosts.append(vh)

        # Ensure that we have one or more VirtualHosts that we can continue
        # with. (one that listens to port configured with --http-01-port)
        found = False
        for vhost in selected_vhosts:
            if any(a.is_wildcard() or a.get_port() == http_port for a in vhost.addrs):
                found = True

        if not found:
            for vh in self._relevant_vhosts():
                selected_vhosts.append(vh)

        # Add the challenge configuration
        for vh in selected_vhosts:
            self._set_up_include_directives(vh)

        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf_pre)
        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf_post)

        if self.configurator.version < (2, 4):
            config_template_pre = self.CONFIG_TEMPLATE22_PRE
            config_template_post = self.CONFIG_TEMPLATE22_POST
        else:
            config_template_pre = self.CONFIG_TEMPLATE24_PRE
            config_template_post = self.CONFIG_TEMPLATE24_POST

        config_text_pre = config_template_pre.format(self.challenge_dir)
        config_text_post = config_template_post.format(self.challenge_dir)

        logger.debug("writing a pre config file with text:\n %s", config_text_pre)
        with open(self.challenge_conf_pre, "w") as new_conf:
            new_conf.write(config_text_pre)
        logger.debug("writing a post config file with text:\n %s", config_text_post)
        with open(self.challenge_conf_post, "w") as new_conf:
            new_conf.write(config_text_post)

    def _matching_vhosts(self, domain):
        """Return all VirtualHost objects that have the requested domain name or
        a wildcard name that would match the domain in ServerName or ServerAlias
        directive.
        """
        matching_vhosts = []
        for vhost in self.configurator.vhosts:
            if self.configurator.domain_in_names(vhost.get_names(), domain):
                # domain_in_names also matches the exact names, so no need
                # to check "domain in vhost.get_names()" explicitly here
                matching_vhosts.append(vhost)

        return matching_vhosts

    def _relevant_vhosts(self):
        http01_port = str(self.configurator.config.http01_port)
        relevant_vhosts = []
        for vhost in self.configurator.vhosts:
            if any(a.is_wildcard() or a.get_port() == http01_port for a in vhost.addrs):
                if not vhost.ssl:
                    relevant_vhosts.append(vhost)
        if not relevant_vhosts:
            raise errors.PluginError(
                "Unable to find a virtual host listening on port {0} which is"
                " currently needed for Certbot to prove to the CA that you"
                " control your domain. Please add a virtual host for port"
                " {0}.".format(http01_port))

        return relevant_vhosts

    def _set_up_challenges(self):
        if not os.path.isdir(self.challenge_dir):
            filesystem.makedirs(self.challenge_dir, 0o755)

        responses = []
        for achall in self.achalls:
            responses.append(self._set_up_challenge(achall))

        return responses

    def _set_up_challenge(self, achall):
        response, validation = achall.response_and_validation()

        name = os.path.join(self.challenge_dir, achall.chall.encode("token"))

        self.configurator.reverter.register_file_creation(True, name)
        with open(name, 'wb') as f:
            f.write(validation.encode())
        filesystem.chmod(name, 0o644)

        return response

    def _set_up_include_directives(self, vhost):
        """Includes override configuration to the beginning and to the end of
        VirtualHost. Note that this include isn't added to Augeas search tree"""

        if vhost not in self.moded_vhosts:
            logger.debug(
                "Adding a temporary challenge validation Include for name: %s in: %s",
                vhost.name, vhost.filep)
            self.configurator.parser.add_dir_beginning(
                vhost.path, "Include", self.challenge_conf_pre)
            self.configurator.parser.add_dir(
                vhost.path, "Include", self.challenge_conf_post)

            if not vhost.enabled:
                self.configurator.parser.add_dir(
                    get_aug_path(self.configurator.parser.loc["default"]),
                    "Include", vhost.filep)

            self.moded_vhosts.add(vhost)
