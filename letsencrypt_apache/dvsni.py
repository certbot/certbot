"""ApacheDVSNI"""
import logging
import os

from letsencrypt_apache import parser


class ApacheDvsni(object):
    """Class performs DVSNI challenges within the Apache configurator.

    :ivar configurator: ApacheConfigurator object
    :type configurator: :class:`~apache.configurator.ApacheConfigurator`

    :ivar list achalls: Annotated :class:`~letsencrypt.client.achallenges.DVSNI`
        challenges.

    :param list indices: Meant to hold indices of challenges in a
        larger array. ApacheDvsni is capable of solving many challenges
        at once which causes an indexing issue within ApacheConfigurator
        who must return all responses in order.  Imagine ApacheConfigurator
        maintaining state about where all of the SimpleHTTPS Challenges,
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
    def __init__(self, configurator):
        self.configurator = configurator
        self.achalls = []
        self.indices = []
        self.challenge_conf = os.path.join(
            configurator.config.config_dir, "le_dvsni_cert_challenge.conf")
        # self.completed = 0

    def add_chall(self, achall, idx=None):
        """Add challenge to DVSNI object to perform at once.

        :param achall: Annotated DVSNI challenge.
        :type achall: :class:`letsencrypt.client.achallenges.DVSNI`

        :param int idx: index to challenge in a larger array

        """
        self.achalls.append(achall)
        if idx is not None:
            self.indices.append(idx)

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
                logging.error(
                    "No vhost exists with servername or alias of: %s",
                    achall.domain)
                logging.error("No _default_:443 vhost exists")
                logging.error("Please specify servernames in the Apache config")
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

    def _setup_challenge_cert(self, achall, s=None):
        # pylint: disable=invalid-name
        """Generate and write out challenge certificate."""
        cert_path = self.get_cert_file(achall)
        # Register the path before you write out the file
        self.configurator.reverter.register_file_creation(True, cert_path)

        cert_pem, response = achall.gen_cert_and_response(s)

        # Write out challenge cert
        with open(cert_path, "w") as cert_chall_fd:
            cert_chall_fd.write(cert_pem)

        return response

    def _mod_config(self, ll_addrs):
        """Modifies Apache config files to include challenge vhosts.

        Result: Apache config includes virtual servers for issued challs

        :param list ll_addrs: list of list of
            :class:`letsencrypt.client.plugins.apache.obj.Addr` to apply

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
        :type achall: :class:`letsencrypt.client.achallenges.DVSNI`

        :param list ip_addrs: addresses of challenged domain
            :class:`list` of type :class:`~apache.obj.Addr`

        :returns: virtual host configuration text
        :rtype: str

        """
        ips = " ".join(str(i) for i in ip_addrs)
        document_root = os.path.join(
            self.configurator.config.config_dir, "dvsni_page/")
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

    def get_cert_file(self, achall):
        """Returns standardized name for challenge certificate.

        :param achall: Annotated DVSNI challenge.
        :type achall: :class:`letsencrypt.client.achallenges.DVSNI`

        :returns: certificate file name
        :rtype: str

        """
        return os.path.join(
            self.configurator.config.work_dir, achall.nonce_domain + ".crt")
