"""ApacheDVSNI"""
import logging
import os

from letsencrypt.plugins import common

from letsencrypt_apache import parser


logger = logging.getLogger(__name__)


class ApacheDvsni(common.Dvsni):
    """Class performs DVSNI challenges within the Apache configurator.

    :ivar configurator: ApacheConfigurator object
    :type configurator: :class:`~apache.configurator.ApacheConfigurator`

    :ivar list achalls: Annotated :class:`~letsencrypt.achallenges.DVSNI`
        challenges.

    :param list indices: Meant to hold indices of challenges in a
        larger array. ApacheDvsni is capable of solving many challenges
        at once which causes an indexing issue within ApacheConfigurator
        who must return all responses in order.  Imagine ApacheConfigurator
        maintaining state about where all of the SimpleHTTP Challenges,
        Dvsni Challenges belong in the response array.  This is an optional
        utility.

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

    def perform(self):
        """Peform a DVSNI challenge."""
        if not self.achalls:
            return []
        # Save any changes to the configuration as a precaution
        # About to make temporary changes to the config
        self.configurator.save()

        addresses = []
        default_addr = "*:443"
        for achall in self.achalls:
            vhost = self.configurator.choose_vhost(achall.domain)
            if vhost is None:
                logger.error(
                    "No vhost exists with servername or alias of: %s. "
                    "No _default_:443 vhost exists. Please specify servernames "
                    "in the Apache config", achall.domain)
                return None

            # TODO - @jdkasten review this code to make sure it makes sense
            self.configurator.make_server_sni_ready(vhost, default_addr)

            for addr in vhost.addrs:
                if "_default_" == addr.get_addr():
                    addresses.append([default_addr])
                    break
            else:
                addresses.append(list(vhost.addrs))

        responses = []

        # Create all of the challenge certs
        for achall in self.achalls:
            responses.append(self._setup_challenge_cert(achall))

        # Setup the configuration
        self._mod_config(addresses)

        # Save reversible changes
        self.configurator.save("SNI Challenge", True)

        return responses

    def _mod_config(self, ll_addrs):
        """Modifies Apache config files to include challenge vhosts.

        Result: Apache config includes virtual servers for issued challs

        :param list ll_addrs: list of list of `~.common.Addr` to apply

        """
        # TODO: Use ip address of existing vhost instead of relying on FQDN
        config_text = "<IfModule mod_ssl.c>\n"
        for idx, lis in enumerate(ll_addrs):
            config_text += self._get_config_text(self.achalls[idx], lis)
        config_text += "</IfModule>\n"

        self._conf_include_check(self.configurator.parser.loc["default"])
        self.configurator.reverter.register_file_creation(
            True, self.challenge_conf)

        with open(self.challenge_conf, "w") as new_conf:
            new_conf.write(config_text)

    def _conf_include_check(self, main_config):
        """Adds DVSNI challenge conf file into configuration.

        Adds DVSNI challenge include file if it does not already exist
        within mainConfig

        :param str main_config: file path to main user apache config file

        """
        if len(self.configurator.parser.find_dir(
                parser.case_i("Include"), self.challenge_conf)) == 0:
            # print "Including challenge virtual host(s)"
            self.configurator.parser.add_dir(
                parser.get_aug_path(main_config),
                "Include", self.challenge_conf)

    def _get_config_text(self, achall, ip_addrs):
        """Chocolate virtual server configuration text

        :param achall: Annotated DVSNI challenge.
        :type achall: :class:`letsencrypt.achallenges.DVSNI`

        :param list ip_addrs: addresses of challenged domain
            :class:`list` of type `~.common.Addr`

        :returns: virtual host configuration text
        :rtype: str

        """
        ips = " ".join(str(i) for i in ip_addrs)
        document_root = os.path.join(
            self.configurator.config.work_dir, "dvsni_page/")
        # TODO: Python docs is not clear how mutliline string literal
        # newlines are parsed on different platforms. At least on
        # Linux (Debian sid), when source file uses CRLF, Python still
        # parses it as "\n"... c.f.:
        # https://docs.python.org/2.7/reference/lexical_analysis.html
        return self.VHOST_TEMPLATE.format(
            vhost=ips, server_name=achall.nonce_domain,
            ssl_options_conf_path=self.configurator.parser.loc["ssl_options"],
            cert_path=self.get_cert_file(achall), key_path=achall.key.file,
            document_root=document_root).replace("\n", os.linesep)
