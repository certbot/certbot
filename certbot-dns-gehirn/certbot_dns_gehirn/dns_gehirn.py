"""DNS Authenticator for Gehirn DNS DNS."""
import logging

import requests
from requests.auth import HTTPBasicAuth

import zope.interface

from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Gehirn DNS

    This Authenticator uses the Gehirn DNS API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record' \
                  + '(if you are using Gehirn DNS for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Gehirn Infrastructure Service credentials file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a ' \
               + 'dns-01 challenge using the Gehirn DNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Gehirn Infrastructure Service credentials file',
            {
                'api-token': 'API Token for Gehirn Infrastructure Service API',
                'api-secret': 'API Secret for Gehirn Infrastructure Service API'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_gehirn_dns_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_gehirn_dns_client().del_txt_record(domain, validation_name, validation)

    def _get_gehirn_dns_client(self):
        return _GehirnDNSLexiconClient(
            self.credentials.conf('api-token'),
            self.credentials.conf('api-secret'),
            self.ttl
        )

class _GehirnDNSProvider(object):

    def __init__(self, options):
        self.domain_id = None
        self.api_endpoint = 'https://api.gis.gehirn.jp/dns/v1'
        self.options = options

    def authenticate(self): # pylint: disable=missing-docstring,no-self-use
        payload = self._get('/zones')

        domains = [item for item in payload if item['name'] == self.options['domain']]
        if not domains:
            raise Exception('No domain found')

        self.domain_id = domains[0]["id"]

    def get_current_version_id(self): # pylint: disable=missing-docstring,no-self-use
        payload = self._get('/zones/{}'.format(self.domain_id))
        return payload["current_version_id"]

    def create_record(self, rtype, name, content): # pylint: disable=missing-docstring,no-self-use
        name = name + "."
        if rtype != "TXT":
            raise NotImplementedError()

        record = self.get_txt_record(name)
        if not record:
            record = {
                "name": name,
                "type": "TXT",
                "ttl": self.options["ttl"],
                "enable_alias": False,
                "records": []
            }

        record["records"].append({"data": content})

        version_id = self.get_current_version_id()

        if len(record["records"]) == 1:
            # create
            self._request(
                'POST',
                '/zones/{}/versions/{}/records'.format(self.domain_id, version_id),
                record
            )
        else:
            # update
            self._request(
                'PUT',
                '/zones/{}/versions/{}/records/{}'.format(self.domain_id, version_id, record["id"]),
                record
            )

    def delete_record(self, identifier=None, rtype=None, name=None, content=None):
        # pylint: disable=missing-docstring,no-self-use
        del identifier
        name = name + "."
        if rtype != "TXT":
            raise NotImplementedError()

        version_id = self.get_current_version_id()

        record = self.get_txt_record(name)

        if record is None:
            return

        index = -1
        for i, data in enumerate(record["records"]):
            if data["data"] == content:
                index = i
                break

        if index < 0:
            return

        del record["records"][index]

        if len(record["records"]) == 0:
            # DELETE
            self._request(
                'DELETE',
                '/zones/{}/versions/{}/records/{}'.format(self.domain_id, version_id, record['id']),
            )
        else:
            # PUT
            self._request(
                'PUT',
                '/zones/{}/versions/{}/records/{}'.format(self.domain_id, version_id, record['id']),
                record
            )


    def get_txt_record(self, name): # pylint: disable=missing-docstring,no-self-use
        version_id = self.get_current_version_id()
        payload = self._request(
            'GET',
            '/zones/{}/versions/{}/records'.format(self.domain_id, version_id)
        )
        for record in payload:
            if record['type'] == 'TXT' and record['name'] == name:
                return record
        return None

    def _get(self, url='/', query_params=None):
        return self._request('GET', url, query_params=query_params)

    def _request(self, action='GET', url='/', data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}

        default_headers = {
            'Accept': 'application/json',
            # 'Content-Type': 'application/json',
        }

        r = requests.request(action, self.api_endpoint + url, params=query_params,
                             json=data,
                             headers=default_headers,
                             auth=HTTPBasicAuth(
                                self.options['auth_token'],
                                self.options['auth_secret']
                            ))
        r.raise_for_status()  # if the request fails for any reason, throw an error.

        if action == 'DELETE':
            return r.text
        return r.json()

class _GehirnDNSLexiconClient(dns_common_lexicon.LexiconClient):

    def __init__(self, api_token, api_secret, ttl):
        super(_GehirnDNSLexiconClient, self).__init__()

        self.provider = _GehirnDNSProvider({
            'auth_token': api_token,
            'auth_secret': api_secret,
            'ttl': ttl,
        })
