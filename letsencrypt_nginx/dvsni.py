"""NginxDVSNI"""
import logging

from letsencrypt_apache.dvsni import ApacheDvsni


class NginxDvsni(ApacheDvsni):
    """Class performs DVSNI challenges within the Nginx configurator.

    .. todo:: This is basically copied-and-pasted from the Apache equivalent.
        It doesn't actually work yet.

    :ivar configurator: NginxConfigurator object
    :type configurator: :class:`~nginx.configurator.NginxConfigurator`

    :ivar list achalls: Annotated :class:`~letsencrypt.achallenges.DVSNI`
        challenges.

    :param list indices: Meant to hold indices of challenges in a
        larger array. NginxDvsni is capable of solving many challenges
        at once which causes an indexing issue within NginxConfigurator
        who must return all responses in order.  Imagine NginxConfigurator
        maintaining state about where all of the SimpleHTTPS Challenges,
        Dvsni Challenges belong in the response array.  This is an optional
        utility.

    :param str challenge_conf: location of the challenge config file

    """

    def perform(self):
        """Perform a DVSNI challenge on Nginx."""
        if not self.achalls:
            return []

        self.configurator.save()

        addresses = []
        for achall in self.achalls:
            vhost = self.configurator.choose_vhost(achall.domain)
            if vhost is None:
                logging.error(
                    "No nginx vhost exists with servername or alias of: %s",
                    achall.domain)
                logging.error("No default 443 nginx vhost exists")
                logging.error("Please specify servernames in the Nginx config")
                return None
            else:
                addresses.append(list(vhost.addrs))

        responses = []

        # Create all of the challenge certs
        # for achall in self.achalls:
        #     responses.append(self._setup_challenge_cert(achall))

        # Setup the configuration
        # self._mod_config(addresses)

        # Save reversible changes
        self.configurator.save("SNI Challenge", True)

        return responses
