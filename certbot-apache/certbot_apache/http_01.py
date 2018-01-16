"""A class that performs HTTP-01 challenges for Apache"""
import logging
import os

from certbot.plugins import common

logger = logging.getLogger(__name__)

class ApacheHttp01(common.TLSSNI01):
    """Class that performs HTPP-01 challenges within the Apache configurator."""

    CONFIG_TEMPLATE = """\
        Alias /.well-known/acme-challenge {0}"
        <IfModule mod_proxy.c>
            ProxyPass "/.well-known/acme-challenge" !
        </IfModule>
    """

    def __init__(self, *args, **kwargs):
        super(ApacheHttp01, self).__init__(*args, **kwargs)
        self.challenge_conf = os.path.join(
            self.configurator.conf("challenge-location"),
            "le_http_01_challenge.conf")
        self.challenge_dir = os.path.join(
            self.configurator.config.work_dir,
            "http_challenges")

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
            needed_modules = ["alias"]
            if self.configurator.version < (2, 4):
                needed_modules.append("authz_host")
            else:
                needed_modules.append("authz_core")
            for mod in needed_modules:
                if mod + "_module" not in self.configurator.parser.modules:
                    self.configurator.enable_mod(mod, temp=True)

    def _mod_config(self):
        self.configurator.parser.add_include(
            self.configurator.parser.loc["default"], self.challenge_conf)
        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf)

        config_text = self.CONFIG_TEMPLATE.format(self.challenge_dir)

        logger.debug("writing a config file with text:\n %s", config_text)
        with open(self.challenge_conf, "w") as new_conf:
            new_conf.write(config_text)

        # Set up temporary directives that disable directives potentially
        # interfering with the challenge validation
        self._set_up_challenge_overrides()


    def _set_up_challenges(self):
        if not os.path.isdir(self.challenge_dir):
            os.makedirs(self.challenge_dir)
            os.chmod(self.challenge_dir, 0o755)

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
        os.chmod(name, 0o644)

        return response

    def _set_up_challenge_overrides(self):
        """Set up overrides for all challenge vhosts"""
        for chall in self.achalls:
            vh = self.configurator.find_best_http_vhost(chall.domain)
            if vh:
                self._set_up_directory_directive(vh)
                self._set_up_rewrite_directives(vh)

    def _set_up_rewrite_directives(self, vhost):
        """Creates mod_rewrite in VirtualHost"""

        if self.configurator.version < (2, 4):
            rewrite_rule = ["(.*)", self.challenge_dir+"$1", "[L,S=9999]"]
        else:
            rewrite_rule = ["(.*)", self.challenge_dir+"$1", "[END]"]

        self.configurator.parser.add_dir(vhost.path, "RewriteEngine", "on")
        self.configurator.parser.add_dir(vhost.path, "RewriteRule", rewrite_rule)

    def _set_up_directory_directive(self, vhost):
        """Creates <Directory> directive for the challenge directory"""

        self.configurator.aug.insert(vhost.path + "/arg", "Directory", False)
        self.configurator.aug.set(vhost.path + "/Directory[1]/arg",
                                  self.challenge_dir)
        if self.configurator.version < (2, 4):
            self.configurator.parser.add_dir(vhost.path+"/Directory[1]",
                                             "Order", ["allow", "deny"])
            self.configurator.parser.add_dir(vhost.path+"/Directory[1]",
                                             "Allow", ["from", "all"])

        else:
            self.configurator.parser.add_dir(vhost.path+"/Directory[1]",
                                             "Require", ["all", "granted"])


