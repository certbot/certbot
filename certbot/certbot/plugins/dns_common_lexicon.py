"""Common code for DNS Authenticator Plugins built on Lexicon."""
import logging
from typing import Any
from typing import Dict
from typing import Mapping
from typing import Optional
from typing import Union

from requests.exceptions import HTTPError
from requests.exceptions import RequestException

from certbot import errors
from certbot.plugins import dns_common

# Lexicon is not declared as a dependency in Certbot itself,
# but in the Certbot plugins backed by Lexicon.
# So we catch import error here to allow this module to be
# always importable, even if it does not make sense to use it
# if Lexicon is not available, obviously.
try:
    from lexicon.config import ConfigResolver
    from lexicon.providers.base import Provider
except ImportError:
    ConfigResolver = None
    Provider = None

logger = logging.getLogger(__name__)


class LexiconClient:
    """
    Encapsulates all communication with a DNS provider via Lexicon.
    """

    def __init__(self) -> None:
        self.provider: Provider

    def add_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises errors.PluginError: if an error occurs communicating with the DNS Provider API
        """
        self._find_domain_id(domain)

        try:
            self.provider.create_record(rtype='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error adding TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error adding TXT record: {0}'.format(e))

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
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
            self.provider.delete_record(rtype='TXT', name=record_name, content=record_content)
        except RequestException as e:
            logger.debug('Encountered error deleting TXT record: %s', e, exc_info=True)

    def _find_domain_id(self, domain: str) -> None:
        """
        Find the domain_id for a given domain.

        :param str domain: The domain for which to find the domain_id.
        :raises errors.PluginError: if the domain_id cannot be found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain)

        for domain_name in domain_name_guesses:
            try:
                if hasattr(self.provider, 'options'):
                    # For Lexicon 2.x
                    self.provider.options['domain'] = domain_name
                else:
                    # For Lexicon 3.x
                    self.provider.domain = domain_name

                self.provider.authenticate()

                return  # If `authenticate` doesn't throw an exception, we've found the right name
            except HTTPError as e:
                result1 = self._handle_http_error(e, domain_name)

                if result1:
                    raise result1
            except Exception as e:  # pylint: disable=broad-except
                result2 = self._handle_general_error(e, domain_name)

                if result2:
                    raise result2  # pylint: disable=raising-bad-type

        raise errors.PluginError('Unable to determine zone identifier for {0} using zone names: {1}'
                                 .format(domain, domain_name_guesses))

    def _handle_http_error(self, e: HTTPError, domain_name: str) -> Optional[errors.PluginError]:
        return errors.PluginError('Error determining zone identifier for {0}: {1}.'
                                  .format(domain_name, e))

    def _handle_general_error(self, e: Exception, domain_name: str) -> Optional[errors.PluginError]:
        if not str(e).startswith('No domain found'):
            return errors.PluginError('Unexpected error determining zone identifier for {0}: {1}'
                                      .format(domain_name, e))
        return None


def build_lexicon_config(lexicon_provider_name: str,
                         lexicon_options: Mapping[str, Any], provider_options: Mapping[str, Any]
                         ) -> Union[ConfigResolver, Dict[str, Any]]:
    """
    Convenient function to build a Lexicon 2.x/3.x config object.
    :param str lexicon_provider_name: the name of the lexicon provider to use
    :param dict lexicon_options: options specific to lexicon
    :param dict provider_options: options specific to provider
    :return: configuration to apply to the provider
    :rtype: ConfigurationResolver or dict
    """
    config: Union[ConfigResolver, Dict[str, Any]] = {'provider_name': lexicon_provider_name}
    config.update(lexicon_options)
    if not ConfigResolver:
        # Lexicon 2.x
        config.update(provider_options)
    else:
        # Lexicon 3.x
        provider_config: Dict[str, Any] = {}
        provider_config.update(provider_options)
        config[lexicon_provider_name] = provider_config
        config = ConfigResolver().with_dict(config).with_env()

    return config
