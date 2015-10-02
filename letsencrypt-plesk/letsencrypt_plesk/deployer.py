"""PleskDeployer"""
import logging

logger = logging.getLogger(__name__)


class PleskDeployer(object):
    """Class performs deploy operations within the Plesk configurator."""

    def __init__(self, plesk_api_client, domain):
        """Initialize Plesk Certificate Deployer"""
        self.plesk_api_client = plesk_api_client
        self.domain = domain

    def install_cert(self, cert_path, key_path, chain_path=None):
        request = {'packet': {
            'certificate': {
                'install': [
                    {'name': ("Lets Encrypt %s" % self.domain)},
                    {'webspace': self.domain},  # TODO get webspace name
                    {'content': [
                        {'csr': {}},
                        {'pvt': self._read_file(key_path)},
                        {'cert': self._read_file(cert_path)},
                        {'ca': self._read_file(chain_path) if chain_path else {}}
                    ]}
                ]
            }
        }}
        response = self.plesk_api_client.request(request)
        logger.debug(response)

    @staticmethod
    def _read_file(path):
        with open(path) as f:
            return f.read()
