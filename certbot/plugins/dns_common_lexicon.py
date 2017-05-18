"""Common code for DNS Authenticator Plugins built on Lexicon."""

import logging

from requests.exceptions import HTTPError, RequestException

from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


class LexiconClient(object):
    """
    Encapsulates all communication with a DNS provider via Lexicon.
    """

    def __init__(self):
        self.provider = None

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises errors.PluginError: if an error occurs communicating with the DNS Provider API
        """
        self._find_domain_id(domain)

        try:
            self.provider.create_record(type='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error adding TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error adding TXT record: {0}'.format(e))

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises errors.PluginError: if an error occurs communicating with the DNS Provider  API
        """
        try:
            self._find_domain_id(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding domain_id during deletion: %s', e,
                         exc_info=True)
            return

        try:
            self.provider.delete_record(type='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error deleting TXT record: %s', e, exc_info=True)

    def _find_domain_id(self, domain):
        """
        Find the domain_id for a given domain.

        :param str domain: The domain for which to find the domain_id.
        :raises errors.PluginError: if the domain_id cannot be found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain)

        for domain_name in domain_name_guesses:
            try:
                self.provider.options['domain'] = domain_name

                self.provider.authenticate()

                return  # If `authenticate` doesn't throw an exception, we've found the right name
            except HTTPError as e:
                result = self._handle_http_error(e, domain_name)

                if result:
                    raise result
            except Exception as e:  # pylint: disable=broad-except
                result = self._handle_general_error(e, domain_name)

                if result:
                    raise result

        raise errors.PluginError('Unable to determine zone identifier for {0} using zone names: {1}'
                                 .format(domain, domain_name_guesses))

    def _handle_http_error(self, e, domain_name):
        return errors.PluginError('Error determining zone identifier for {0}: {1}.'
                                  .format(domain_name, e))

    def _handle_general_error(self, e, domain_name):
        if not str(e).startswith('No domain found'):
            return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}'
                                      .format(domain_name, e))
