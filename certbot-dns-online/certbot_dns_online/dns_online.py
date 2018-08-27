"""DNS Authenticator for Online DNS."""
import json
import logging
import requests

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

TOKEN_URL = 'https://console.online.net/fr/api/access'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Online

    This Authenticator uses the Online API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Online for DNS).'
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='Online credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Online API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Online credentials INI file',
            {
                'application_token': 'Token for Online API, obtained from {0}'
                    .format(TOKEN_URL),
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_online_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_online_client().del_txt_record(domain, validation_name, validation)

    def _get_online_client(self):
        return _OnlineClient(
            self.credentials.conf('application-token')
        )


class _OnlineClient(object):
    """
    Encapsulates all communication with Online API.
    """

    DEFAULT_ENDPOINT = 'https://api.online.net'

    def __init__(self, api_token):
        self.api_token = api_token

    def find_domain(self, domain_name):
        """
        Call the Online Rest Api to find the domain name to use
        """
        headers = {
            "Authorization": "Bearer " + self.api_token
        }

        url = "{}{}". \
            format(self.DEFAULT_ENDPOINT, '/api/v1/domain/')

        result = requests.get(url, headers=headers)

        if result.status_code != 200:
            msg = 'Error communicating with the Online API : {0}'.format(result.json())
            raise errors.PluginError(msg)

        # find the domain to use from the list
        while len(domain_name) > 0:
            for domain in result.json():
                if domain_name == domain["name"]:
                    return domain_name
            parts = domain_name.split('.', 1)
            logger.debug(parts)
            if len(parts) > 1:
                domain_name = parts[1]
            else:
                domain_name = ""

        msg = "Can't found domain to use with the Online API : {0}".format(result.json())
        raise errors.PluginError(msg)

    def update(self, args):
        """
        Call the Online Rest Api to update/delete record
        """
        headers = {
            "Authorization": "Bearer " + self.api_token
        }

        url = "{}{}{}{}". \
            format(self.DEFAULT_ENDPOINT, '/api/v1/domain/', args['zone'], '/version/active')

        data = {
            "name": args['name'],
            "type": args['type'],
            "records": [
                {
                    "name": args['name'],
                    "type": args['type'],
                    "ttl": args['ttl'],
                    "data": args['content'],
                }
            ]
        }

        if data["type"] == "MX":
            data["records"][0]["priority"] = args['priority']

        if args['state'] == 'present':
            if args['unique']:
                change_type = 'REPLACE'
            else:
                change_type = 'ADD'

        else:
            change_type = 'DELETE'
            data['records'] = []
            if args['content'] != '':
                data['data'] = args['content']

        data['changeType'] = change_type

        result = requests.patch(url, json.dumps([data]), headers=headers)

        if result.status_code != 204:
            msg = 'Error communicating with the Online API : {0}'.format(result.json())
            raise errors.PluginError(msg)

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.
        :param str domain: The domain to use to look up the Online zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Online API
        """

        domain = self.find_domain(domain)

        data = {
            "name": record_name.replace('.' + domain, ''),
            "zone": domain,
            "type": "TXT",
            "ttl": record_ttl,
            "content": record_content,
            "state": "present",
            "unique": False
        }

        try:
            logger.debug('Attempting to add record to zone %s: %s', domain, record_name)
            self.update(data)

        except Exception as e:
            logger.error('Encountered Error adding TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Online API: {0}'.format(e))

        logger.debug('Successfully added TXT record')

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.
        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.
        Failures are logged, but not raised.
        :param str domain: The domain to use to look up the Online zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        domain = self.find_domain(domain)

        data = {
            "name": record_name.replace('.' + domain, ''),
            "zone": domain,
            "type": "TXT",
            "content": record_content,
            "state": "absent",
            "ttl": 0
        }

        try:
            logger.debug('Attempting to delete record to zone %s: %s', domain, record_name)
            self.update(data)
        except Exception as e:
            logger.error('Encountered Error deleting TXT record: %s', e)
            raise errors.PluginError('Error communicating with the Online API: {0}'.format(e))

        logger.debug('Successfully deleted TXT record')
