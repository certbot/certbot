"""PleskDeployer"""
import logging

from letsencrypt import errors

logger = logging.getLogger(__name__)


class PleskDeployer(object):
    """Class performs deploy operations within the Plesk configurator."""

    def __init__(self, plesk_api_client, domain):
        """Initialize Plesk Certificate Deployer"""
        self.plesk_api_client = plesk_api_client
        self.domain = domain

    def cert_name(self):
        """Return name of the domain certificate in Plesk."""
        return "Lets Encrypt %s" % self.domain

    def get_certs(self):
        """Return list of certificates registered in Plesk."""
        request = {'packet': {
            'certificate': {
                'get-pool': {'filter': {'domain-name': self.domain}}
            }
        }}
        response = self.plesk_api_client.request(request)
        api_result = response['packet']['certificate']['get-pool']['result']
        if 'ok' != api_result['status'] \
                or 'certificates' not in api_result \
                or not isinstance(api_result['certificates'], dict) \
                or 'certificate' not in api_result['certificates']:
            return []
        certs = api_result['certificates']['certificate']
        if isinstance(certs, dict):
            certs = [certs]
        return [cert['name'] for cert in certs]

    def install_cert(self, cert_path, key_path, chain_path=None):
        """Install certificate to the domain repository in Plesk."""
        request = {'packet': {
            'certificate': {
                'install': [
                    {'name': self.cert_name()},
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
        api_result = response['packet']['certificate']['install']['result']
        if 'ok' != api_result['status']:
            error_text = str(api_result['errtext'])
            raise errors.PluginError(
                'Install certificate failure: %s' % error_text)

    @staticmethod
    def _read_file(path):
        if not path:
            return {}
        with open(path) as f:
            return f.read()

    def assign_cert(self):
        """Assign certificate to the domain and enable SSL."""
        request = {'packet': {
            'site': {'set': [
                {'filter': {'name': self.domain}},
                {'values': {'hosting': {'vrt_hst': [
                    {'property': [
                        {'name': 'ssl'},
                        {'value': 'true'},
                    ]},
                    {'property': [
                        {'name': 'certificate_name'},
                        {'value': self.cert_name()},
                    ]},
                ]}}}
            ]}
        }}
        response = self.plesk_api_client.request(request)
        api_result = response['packet']['site']['set']['result']
        if 'ok' != api_result['status']:
            error_text = str(api_result['errtext'])
            raise errors.PluginError(
                'Assign certificate failure: %s' % error_text)
