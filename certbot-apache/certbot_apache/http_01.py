"""A class that performs HTTP-01 challenges for Apache"""
import logging
import os
import shutil
import tempfile

from certbot.plugins import common

logger = logging.getLogger(__name__)

class ApacheHttp01(common.TLSSNI01):
    """Class that performs HTPP-01 challenges within the Apache configurator."""

    CONFIG_TEMPLATE24 = """\
Alias /.well-known/acme-challenge {0}

<Directory {0} >
    Require all granted
</Directory>

"""

    CONFIG_TEMPLATE22 = """\
Alias /.well-known/acme-challenge {0}

<Directory {0} >
    Order allow,deny
    Allow from all
</Directory>

"""

    def __init__(self, *args, **kwargs):
        super(ApacheHttp01, self).__init__(*args, **kwargs)
        self.challenge_conf = os.path.join(
            self.configurator.conf("challenge-location"),
            "le_http_01_challenge.conf")
        self.challenge_dir = None

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

    def cleanup(self):
        """Cleanup the challenge directory."""
        shutil.rmtree(self.challenge_dir, ignore_errors=True)
        self.challenge_dir = None

    def prepare_http01_modules(self):
        """Make sure that we have the needed modules available for http01"""

        if self.configurator.conf("handle-modules"):
            if "alias_module" not in self.configurator.parser.modules:
                self.configurator.enable_mod("alias", temp=True)

    def _mod_config(self):
        self.configurator.parser.add_include(
            self.configurator.parser.loc["default"], self.challenge_conf)
        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf)

        if self.configurator.version < (2, 4):
            config_template = self.CONFIG_TEMPLATE22
        else:
            config_template = self.CONFIG_TEMPLATE24
        config_text = config_template.format(self.challenge_dir)

        logger.debug("writing a config file with text:\n %s", config_text)
        with open(self.challenge_conf, "w") as new_conf:
            new_conf.write(config_text)

    def _set_up_challenges(self):
        self.challenge_dir = tempfile.mkdtemp()
        os.chmod(self.challenge_dir, 0o755)

        responses = []
        for achall in self.achalls:
            responses.append(self._set_up_challenge(achall))

        return responses

    def _set_up_challenge(self, achall):
        response, validation = achall.response_and_validation()

        name = os.path.join(self.challenge_dir, achall.chall.encode("token"))
        with open(name, 'wb') as f:
            f.write(validation.encode())
        os.chmod(name, 0o644)

        return response
