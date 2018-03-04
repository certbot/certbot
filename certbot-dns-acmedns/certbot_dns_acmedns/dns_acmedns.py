"""DNS Authenticator for ACME-DNS."""
import json
import logging
import requests
import time

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for ACME-DNS

    This Authenticator uses the ACME-DNS API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using '
                   'ACME-DNS to handle the validation). ')

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        # Override propagation delay, as it's not needed for ACME-DNS
        self.config.dns_acmedns_propagation_seconds = 0
        self.domain_map = self.storage.fetch("domain_map")
        self.acmedns_url = self.config.dns_acmedns_url
        import ipdb;ipdb.set_trace()
        self.force_register = self.config.dns_acmedns_force-register
        if not self.domain_map:
            # Pre-existing domain_map not found, initialize it
            self.domain_map = dict()

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('url', help='URL to ACME-DNS instance root')
        add('force-register', help='Force registering acme-dns account (ignore saved)')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ('This plugin handles DNS challenge validation using ACME-DNS service. '
                'It also handles creating and managing individual ACME-DNS credentials '
                'for each of your domain names. You will be prompted to manually create '
                'a CNAME record for each of your domains. This is a one time only action.')

    def _perform(self, domain, _validation_name, validation):
        acc = None
        if not self.force_register:
            acc = self.get_account(domain)
        if not acc:
            # Handle new account creation and storage
            acmedns_client = self._get_acmedns_client(self.acmedns_url)
            acc = acmedns_client.register_account()
            acc['acmedns_url'] = self.acmedns_url
            self.domain_map[domain] = acc
            self.storage.put("domain_map", self.domain_map)
            self.display_instructions(domain, acc)
        else:
            acmedns_client = self._get_acmedns_client(acc['acmedns_url'])
        acmedns_client.update_txt_record(acc, validation)
        self.storage.save()
        time.sleep(2)

    def _get_acmedns_client(self, url):
        return _AcmeDnsClient(url)

    def display_instructions(self, domain, account):
        msg = ("Please add the following CNAME record to your main DNS zone for domain "
              "{0}:\n\n _acme-challenge.{0} CNAME {1}".format(domain, account['fulldomain']))
        print(msg)

    def get_account(self, domain):
        """
        Tries to fetch an existing ACME-DNS account from the domain map

        :param str domain: Domain which account to fetch

        :returns:
        """
        try:
            return self.domain_map[domain]
        except KeyError:
            # The domain in question is not in the storage
            return None

    def _cleanup(self, _domain, _validation_name, _validation):
        """Cleanup is NOOP for ACME-DNS"""
        pass

    def _setup_credentials(self, *args, **kwargs):
        """Setup credentials is NOOP for ACME-DNS"""
        pass


class _AcmeDnsClient(object):
    """
    Handles the communication with ACME-DNS API
    """

    def __init__(self, acmedns_url):
        self.acmedns_url = acmedns_url

    def register_account(self):
        """
        Registers a new ACME-DNS account
        """

        res = requests.post(self.acmedns_url+"/register")
        if res.status_code == 201:
            # The request was successful
            return res.json()
        else:
            # Encountered an error
            raise errors.Error("Encountered an error while trying to register a new "
                               "ACME-DNS account.")

    def update_txt_record(self, account, txt):
        """
        Updates the TXT challenge record to ACME-DNS subdomain.
        """
        if account == None:
            raise errors.Error("Error while trying to fetch account data from "
                               "internal storage, this should not happen.")
        update = {"subdomain": account['subdomain'], "txt": txt}
        headers = {"X-Api-User": account['username'],
                   "X-Api-Key": account['password'],
                   "Content-Type": "application/json"}
        res = requests.post(self.acmedns_url+"/update",
                            headers=headers,
                            data=json.dumps(update))
        if res.status_code == 200:
            # Successful update
            return
        else:
            raise errors.Error("Encountered an error while trying to update the TXT "
                               "challenge token for ACME-DNS")
