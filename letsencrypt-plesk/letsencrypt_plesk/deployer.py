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
        self.cert_data = self.key_data = self.chain_data = None
        self.cert_installed = self.cert_assigned = False

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

    def init_cert(self, cert_data, key_data, chain_data=None):
        """Initialize certificate data."""
        self.cert_data = cert_data
        self.key_data = key_data
        self.chain_data = chain_data if chain_data else {}

    def install_cert(self):
        """Install certificate to the domain repository in Plesk."""
        request = {'packet': {
            'certificate': {
                'install': [
                    {'name': self.cert_name()},
                    {'site': self.domain},
                    {'content': [
                        {'csr': {}},
                        {'pvt': self.key_data},
                        {'cert': self.cert_data},
                        {'ca': self.chain_data},
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
        self.cert_installed = True

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
        self.cert_assigned = True

    def remove_cert(self):
        """Remove certificate from the domain repository in Plesk."""
        request = {'packet': {
            'certificate': {
                'remove': [
                    {'filter': {'name': self.cert_name()}},
                    {'site': self.domain},
                ]
            }
        }}
        response = self.plesk_api_client.request(request)
        api_result = response['packet']['certificate']['remove']['result']
        if 'ok' != api_result['status']:
            error_text = str(api_result['errtext'])
            raise errors.PluginError(
                'Remove certificate failure: %s' % error_text)

    def revert(self):
        """Revert changes in Plesk."""
        if self.cert_installed:
            self.remove_cert()
            self.cert_installed = False
        self.cert_assigned = False
