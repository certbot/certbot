"""PleskDeployer"""
import logging

logger = logging.getLogger(__name__)


class PleskDeployer(object):
    """Class performs deploy operations within the Plesk configurator."""

    def __init__(self, plesk_api_client, domain):
        """Initialize Plesk Certificate Deployer"""
        self.plesk_api_client = plesk_api_client
        self.domain = domain

    def get_certs(self):
        """Return list of certificates registered in Plesk."""
        request = {'packet': {
            'certificate': {
                'get-pool': {'filter': {'domain-name': self.domain}}
            }
        }}
        response = self.plesk_api_client.request(request)
        logger.debug(response)
        # TODO parse response
        return []

    def install_cert(self, cert_path, key_path, chain_path=None):
        """Install certificate to the webspace repository in Plesk."""
        request = {'packet': {
            'certificate': {
                'install': [
                    {'name': ("Lets Encrypt %s" % self.domain)},
                    {'site': self.domain},
                    {'content': [
                        {'csr': {}},
                        {'pvt': self._read_file(key_path)},
                        {'cert': self._read_file(cert_path)},
                        {'ca': self._read_file(chain_path)},
                    ]}
                ]
            }
        }}
        response = self.plesk_api_client.request(request)
        logger.debug(response)
        # TODO error handling

    @staticmethod
    def _read_file(path):
        if not path:
            return ''
        with open(path) as f:
            return f.read()
