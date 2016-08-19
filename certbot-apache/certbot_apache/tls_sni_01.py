"""A class that performs TLS-SNI-01 challenges for Apache"""

import os
import logging

from certbot.plugins import common
from certbot.errors import PluginError, MissingCommandlineFlag

from certbot_apache import obj
from certbot_apache import parser

logger = logging.getLogger(__name__)


class ApacheTlsSni01(common.TLSSNI01):
    """Class that performs TLS-SNI-01 challenges within the Apache configurator

    :ivar configurator: ApacheConfigurator object
    :type configurator: :class:`~apache.configurator.ApacheConfigurator`

    :ivar list achalls: Annotated TLS-SNI-01
        (`.KeyAuthorizationAnnotatedChallenge`) challenges.

    :param list indices: Meant to hold indices of challenges in a
        larger array. ApacheTlsSni01 is capable of solving many challenges
        at once which causes an indexing issue within ApacheConfigurator
        who must return all responses in order.  Imagine ApacheConfigurator
        maintaining state about where all of the http-01 Challenges,
        TLS-SNI-01 Challenges belong in the response array.  This is an
        optional utility.

    :param str challenge_conf: location of the challenge config file

    """

    VHOST_TEMPLATE = """\
<VirtualHost {vhost}>
    ServerName {server_name}
    UseCanonicalName on
    SSLStrictSNIVHostCheck on

    LimitRequestBody 1048576

    Include {ssl_options_conf_path}
    SSLCertificateFile {cert_path}
    SSLCertificateKeyFile {key_path}

    DocumentRoot {document_root}
</VirtualHost>

"""

    def __init__(self, *args, **kwargs):
        super(ApacheTlsSni01, self).__init__(*args, **kwargs)

        self.challenge_conf = os.path.join(
            self.configurator.conf("challenge-location"),
            "le_tls_sni_01_cert_challenge.conf")

    def perform(self):
        """Perform a TLS-SNI-01 challenge."""
        if not self.achalls:
            return []
        # Save any changes to the configuration as a precaution
        # About to make temporary changes to the config
        self.configurator.save("Changes before challenge setup", True)

        # Prepare the server for HTTPS
        self.configurator.prepare_server_https(
            str(self.configurator.config.tls_sni_01_port), True)

        responses = []

        # Create all of the challenge certs
        for achall in self.achalls:
            responses.append(self._setup_challenge_cert(achall))

        # Setup the configuration
        addrs = self._mod_config()
        self.configurator.save("Don't lose mod_config changes", True)
        self.configurator.make_addrs_sni_ready(addrs)

        # Save reversible changes
        self.configurator.save("SNI Challenge", True)

        return responses

    def _mod_config(self):
        """Modifies Apache config files to include challenge vhosts.

        Result: Apache config includes virtual servers for issued challs

        :returns: All TLS-SNI-01 addresses used
        :rtype: set

        """
        addrs = set()
        config_text = "<IfModule mod_ssl.c>\n"

        for achall in self.achalls:
            achall_addrs = self._get_addrs(achall)
            addrs.update(achall_addrs)

            config_text += self._get_config_text(achall, achall_addrs)

        config_text += "</IfModule>\n"

        self._conf_include_check(self.configurator.parser.loc["default"])
        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf)

        logger.debug("writing a config file with text:\n %s", config_text)
        with open(self.challenge_conf, "w") as new_conf:
            new_conf.write(config_text)

        return addrs

    def _get_addrs(self, achall):
        """Return the Apache addresses needed for TLS-SNI-01."""
        # TODO: Checkout _default_ rules.
        addrs = set()
        default_addr = obj.Addr(("*", str(
            self.configurator.config.tls_sni_01_port)))

        try:
            vhost = self.configurator.choose_vhost(achall.domain, temp=True)
        except (PluginError, MissingCommandlineFlag):
            # We couldn't find the virtualhost for this domain, possibly
            # because it's a new vhost that's not configured yet (GH #677),
            # or perhaps because there were multiple <VirtualHost> sections
            # in the config file (GH #1042).  See also GH #2600.
            logger.warning("Falling back to default vhost %s...", default_addr)
            addrs.add(default_addr)
            return addrs

        for addr in vhost.addrs:
            if "_default_" == addr.get_addr():
                addrs.add(default_addr)
            else:
                addrs.add(
                    addr.get_sni_addr(
                        self.configurator.config.tls_sni_01_port))

        return addrs

    def _conf_include_check(self, main_config):
        """Add TLS-SNI-01 challenge conf file into configuration.

        Adds TLS-SNI-01 challenge include file if it does not already exist
        within mainConfig

        :param str main_config: file path to main user apache config file

        """
        if len(self.configurator.parser.find_dir(
                parser.case_i("Include"), self.challenge_conf)) == 0:
            # print "Including challenge virtual host(s)"
            logger.debug("Adding Include %s to %s",
                         self.challenge_conf, parser.get_aug_path(main_config))
            self.configurator.parser.add_dir(
                parser.get_aug_path(main_config),
                "Include", self.challenge_conf)

    def _get_config_text(self, achall, ip_addrs):
        """Chocolate virtual server configuration text

        :param .KeyAuthorizationAnnotatedChallenge achall: Annotated
            TLS-SNI-01 challenge.

        :param list ip_addrs: addresses of challenged domain
            :class:`list` of type `~.obj.Addr`

        :returns: virtual host configuration text
        :rtype: str

        """
        ips = " ".join(str(i) for i in ip_addrs)
        document_root = os.path.join(
            self.configurator.config.work_dir, "tls_sni_01_page/")
        # TODO: Python docs is not clear how mutliline string literal
        # newlines are parsed on different platforms. At least on
        # Linux (Debian sid), when source file uses CRLF, Python still
        # parses it as "\n"... c.f.:
        # https://docs.python.org/2.7/reference/lexical_analysis.html
        return self.VHOST_TEMPLATE.format(
            vhost=ips,
            server_name=achall.response(achall.account_key).z_domain,
            ssl_options_conf_path=self.configurator.mod_ssl_conf,
            cert_path=self.get_cert_path(achall),
            key_path=self.get_key_path(achall),
            document_root=document_root).replace("\n", os.linesep)
