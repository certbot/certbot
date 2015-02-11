"""ApacheDVSNI"""
import logging
import os

from letsencrypt.client import challenge_util
from letsencrypt.client import constants

from letsencrypt.client.apache import parser


class ApacheDvsni(object):
    """Class performs DVSNI challenges within the Apache configurator.

    :ivar configurator: ApacheConfigurator object
    :type configurator:
        :class:`letsencrypt.client.apache.configurator.ApacheConfigurator`

    :ivar dvsni_chall: Data required for challenges.
       where DvsniChall tuples have the following fields
       `domain` (`str`), `r_b64` (base64 `str`), `nonce` (hex `str`)
       `key` (:class:`letsencrypt.client.le_util.Key`)
    :type dvsni_chall: `list` of
        :class:`letsencrypt.client.challenge_util.DvsniChall`

    :param list indicies: Meant to hold indices of challenges in a
        larger array. ApacheDvsni is capable of solving many challenges
        at once which causes an indexing issue within ApacheConfigurator
        who must return all responses in order.  Imagine ApacheConfigurator
        maintaining state about where all of the SimpleHttps Challenges,
        Dvsni Challenges belong in the response array.  This is an optional
        utility.

    :param str challenge_conf: location of the challenge config file

    """
    def __init__(self, configurator):
        self.configurator = configurator
        self.dvsni_chall = []
        self.indices = []
        self.challenge_conf = os.path.join(
            configurator.config.config_dir, "le_dvsni_cert_challenge.conf")
        # self.completed = 0

    def add_chall(self, chall, idx=None):
        """Add challenge to DVSNI object to perform at once.

        :param chall: DVSNI challenge info
        :type chall: :class:`letsencrypt.client.challenge_util.DvsniChall`

        :param int idx: index to challenge in a larger array

        """
        self.dvsni_chall.append(chall)
        if idx is not None:
            self.indices.append(idx)

    def perform(self):
        """Peform a DVSNI challenge."""
        if not self.dvsni_chall:
            return None
        # Save any changes to the configuration as a precaution
        # About to make temporary changes to the config
        self.configurator.save()

        addresses = []
        default_addr = "*:443"
        for chall in self.dvsni_chall:
            vhost = self.configurator.choose_vhost(chall.domain)
            if vhost is None:
                logging.error(
                    "No vhost exists with servername or alias of: %s",
                    chall.domain)
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
        for chall in self.dvsni_chall:
            s_b64 = self._setup_challenge_cert(chall)
            responses.append({"type": "dvsni", "s": s_b64})

        # Setup the configuration
        self._mod_config(addresses)

        # Save reversible changes
        self.configurator.save("SNI Challenge", True)

        return responses

    def _setup_challenge_cert(self, chall):
        """Generate and write out challenge certificate."""
        cert_path = self.get_cert_file(chall.nonce)
        # Register the path before you write out the file
        self.configurator.reverter.register_file_creation(True, cert_path)

        cert_pem, s_b64 = challenge_util.dvsni_gen_cert(
            chall.domain, chall.r_b64, chall.nonce, chall.key)

        # Write out challenge cert
        with open(cert_path, "w") as cert_chall_fd:
            cert_chall_fd.write(cert_pem)

        return s_b64

    def _mod_config(self, ll_addrs):
        """Modifies Apache config files to include challenge vhosts.

        Result: Apache config includes virtual servers for issued challs

        :param list ll_addrs: list of list of
            :class:`letsencrypt.client.apache.obj.Addr` to apply

        """
        # TODO: Use ip address of existing vhost instead of relying on FQDN
        config_text = "<IfModule mod_ssl.c>\n"
        for idx, lis in enumerate(ll_addrs):
            config_text += self._get_config_text(
                self.dvsni_chall[idx].nonce, lis,
                self.dvsni_chall[idx].key.file)
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

    def _get_config_text(self, nonce, ip_addrs, dvsni_key_file):
        """Chocolate virtual server configuration text

        :param str nonce: hex form of nonce
        :param list ip_addrs: addresses of challenged domain
            :class:`list` of type :class:`letsencrypt.client.apache.obj.Addr`
        :param str dvsni_key_file: Path to key file

        :returns: virtual host configuration text
        :rtype: str

        """
        ips = " ".join(str(i) for i in ip_addrs)
        document_root = os.path.join(
            self.configurator.config.config_dir, "dvsni_page/")
        return ("<VirtualHost " + ips + ">\n"
                "ServerName " + nonce + constants.DVSNI_DOMAIN_SUFFIX + "\n"
                "UseCanonicalName on\n"
                "SSLStrictSNIVHostCheck on\n"
                "\n"
                "LimitRequestBody 1048576\n"
                "\n"
                "Include " + self.configurator.parser.loc["ssl_options"] + "\n"
                "SSLCertificateFile " + self.get_cert_file(nonce) + "\n"
                "SSLCertificateKeyFile " + dvsni_key_file + "\n"
                "\n"
                "DocumentRoot " + document_root + "\n"
                "</VirtualHost>\n\n")

    def get_cert_file(self, nonce):
        """Returns standardized name for challenge certificate.

        :param str nonce: hex form of nonce

        :returns: certificate file name
        :rtype: str

        """
        return os.path.join(self.configurator.config.work_dir, nonce + ".crt")
