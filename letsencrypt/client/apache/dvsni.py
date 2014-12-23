"""ApacheDVSNI"""
import logging
import os
import pkg_resources
import shutil

from letsencrypt.client import challenge_util
from letsencrypt.client import CONFIG

from letsencrypt.client.apache import parser

class ApacheDVSNI(object):
    """Class performs DVSNI challenges within the Apache configurator.

    :ivar config: ApacheConfigurator object
    :type config: :class:`letsencrypt.client.apache.configurator`

    :ivar dvsni_chall: Data required for challenges.
       where DVSNI_Chall tuples have the following fields
       `domain` (`str`), `r_b64` (base64 `str`), `nonce` (hex `str`)
        `key` (:class:`letsencrypt.client.client.Client.Key`)
    :type dvsni_chall: `list` of
        :class:`letsencrypt.client.challenge_util.DVSNI_Chall`

    """
    def __init__(self, config):
        self.config = config
        self.dvsni_chall = []
        self.indices = []
        # self.completed = 0

    def add_chall(self, chall, idx=None):
        """Add challenge to DVSNI object to perform at once.

        :param chall: DVSNI challenge info
        :type chall: :class:`letsencrypt.client.challenge_util.DVSNI_Chall`

        :param int idx: index to challenge in a larger array

        """
        self.dvsni_chall.append(chall)
        if idx is not None:
            self.indices.append(idx)

    def perform(self):
        """Peform a DVSNI challenge."""
        if not self.dvsni_chall:
            return dict()
        # Save any changes to the configuration as a precaution
        # About to make temporary changes to the config
        self.config.save()

        addresses = []
        default_addr = "*:443"
        for chall in self.dvsni_chall:
            vhost = self.config.choose_virtual_host(chall.domain)
            if vhost is None:
                logging.error(
                    "No vhost exists with servername or alias of: %s",
                    chall.domain)
                logging.error("No _default_:443 vhost exists")
                logging.error("Please specify servernames in the Apache config")
                return None

            # TODO - @jdkasten review this code to make sure it makes sense
            self.config.make_server_sni_ready(vhost, default_addr)

            for addr in vhost.addrs:
                if "_default_" == addr.get_addr():
                    addresses.append([default_addr])
                    break
            else:
                addresses.append(list(vhost.addrs))

        responses = []

        # Create all of the challenge certs
        for chall in self.dvsni_chall:
            cert_path = self.get_cert_file(chall.nonce)
            self.config.register_file_creation(cert_path)
            s_b64 = challenge_util.dvsni_gen_cert(
                cert_path, chall.domain, chall.r_b64, chall.nonce, chall.key)

            responses.append({"type": "dvsni", "s": s_b64})

        # Setup the configuration
        self.mod_config(addresses)

        # Save reversible changes
        self.config.save("SNI Challenge", True)

        return responses

    # def chall_complete(self, chall):
    #     """Used by Authenticator to notify the DVSNI challenge.

    #     :param chall: Challenge info
    #     :type chall: :class:`letsencrypt.client.client.Client.DVSNI_Chall`

    #     """
    #     self.completed += 1
    #     if self.completed < len(self.dvsni_chall):
    #         return False
    #     return True

    # TODO: Variable names
    def mod_config(self, ll_addrs):
        """Modifies Apache config files to include challenge vhosts.

        Result: Apache config includes virtual servers for issued challs

        :param list ll_addrs: list of list of
            :class:`letsencrypt.client.apache.obj.Addr` to apply

        """
        # WARNING: THIS IS A POTENTIAL SECURITY VULNERABILITY
        # THIS SHOULD BE HANDLED BY THE PACKAGE MANAGER
        # AND TAKEN OUT BEFORE RELEASE, INSTEAD
        # SHOWING A NICE ERROR MESSAGE ABOUT THE PROBLEM

        # Check to make sure options-ssl.conf is installed
        # pylint: disable=no-member
        if not os.path.isfile(CONFIG.OPTIONS_SSL_CONF):
            dist_conf = pkg_resources.resource_filename(
                __name__, os.path.basename(CONFIG.OPTIONS_SSL_CONF))
            shutil.copyfile(dist_conf, CONFIG.OPTIONS_SSL_CONF)

        # TODO: Use ip address of existing vhost instead of relying on FQDN
        config_text = "<IfModule mod_ssl.c>\n"
        for idx, lis in enumerate(ll_addrs):
            config_text += self.get_config_text(
                self.dvsni_chall[idx].nonce, lis,
                self.dvsni_chall[idx].key.file)
        config_text += "</IfModule>\n"

        self.conf_include_check(self.config.parser.loc["default"])
        self.config.register_file_creation(True, CONFIG.APACHE_CHALLENGE_CONF)

        with open(CONFIG.APACHE_CHALLENGE_CONF, 'w') as new_conf:
            new_conf.write(config_text)

    def conf_include_check(self, main_config):
        """Adds DVSNI challenge conf file into configuration.

        Adds DVSNI challenge include file if it does not already exist
        within mainConfig

        :param str main_config: file path to main user apache config file

        """
        if len(self.config.parser.find_dir(
                parser.case_i("Include"), CONFIG.APACHE_CHALLENGE_CONF)) == 0:
            # print "Including challenge virtual host(s)"
            self.config.parser.add_dir(parser.get_aug_path(main_config),
                                       "Include", CONFIG.APACHE_CHALLENGE_CONF)

    def get_config_text(self, nonce, ip_addrs, dvsni_key_file):
        """Chocolate virtual server configuration text

        :param str nonce: hex form of nonce
        :param list ip_addrs: addresses of challenged domain
            :class:`list` of type :class:`letsencrypt.client.apache.obj.Addr`
        :param str dvsni_key_file: Path to key file

        :returns: virtual host configuration text
        :rtype: str

        """
        ips = " ".join(str(i) for i in ip_addrs)
        return ("<VirtualHost " + ips + ">\n"
                "ServerName " + nonce + CONFIG.INVALID_EXT + "\n"
                "UseCanonicalName on\n"
                "SSLStrictSNIVHostCheck on\n"
                "\n"
                "LimitRequestBody 1048576\n"
                "\n"
                "Include " + self.config.parser.loc["ssl_options"] + "\n"
                "SSLCertificateFile " + self.get_cert_file(nonce) + "\n"
                "SSLCertificateKeyFile " + dvsni_key_file + "\n"
                "\n"
                "DocumentRoot " + self.config.direc["config"] + "dvsni_page/\n"
                "</VirtualHost>\n\n")

    def get_cert_file(self, nonce):
        """Returns standardized name for challenge certificate.

        :param str nonce: hex form of nonce

        :returns: certificate file name
        :rtype: str

        """
        return self.config.direc["work"] + nonce + ".crt"
