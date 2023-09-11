"""Common code for DNS Authenticator Plugins built on Lexicon."""
import abc
import logging
import sys
from types import ModuleType
from typing import Any
from typing import cast
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Tuple
from typing import Union
import warnings

from requests.exceptions import HTTPError
from requests.exceptions import RequestException

from certbot import configuration
from certbot import errors
from certbot.plugins import dns_common

# Lexicon is not declared as a dependency in Certbot itself,
# but in the Certbot plugins backed by Lexicon.
# So we catch import error here to allow this module to be
# always importable, even if it does not make sense to use it
# if Lexicon is not available, obviously.
try:
    from lexicon.client import Client
    from lexicon.config import ConfigResolver
    from lexicon.interfaces import Provider
except ImportError:  # pragma: no cover
    Client = None
    ConfigResolver = None
    Provider = None

logger = logging.getLogger(__name__)


class LexiconClient:  # pragma: no cover
    """
    Encapsulates all communication with a DNS provider via Lexicon.

    .. deprecated:: 2.7.0
       Please use certbot.dns_common_lexicon.LexiconDNSAuthenticator instead.
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
                         ) -> Union[ConfigResolver, Dict[str, Any]]:  # pragma: no cover
    """
    Convenient function to build a Lexicon 2.x/3.x config object.

    :param str lexicon_provider_name: the name of the lexicon provider to use
    :param dict lexicon_options: options specific to lexicon
    :param dict provider_options: options specific to provider
    :return: configuration to apply to the provider
    :rtype: ConfigurationResolver or dict

    .. deprecated:: 2.7.0
       Please use certbot.dns_common_lexicon.LexiconDNSAuthenticator instead.
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


class LexiconDNSAuthenticator(dns_common.DNSAuthenticator):
    """
    Base class for a DNS authenticator that uses Lexicon client
    as backend to execute DNS record updates
    """

    def __init__(self, config: configuration.NamespaceConfig, name: str):
        super().__init__(config, name)
        self._provider_options: List[Tuple[str, str, str]] = []
        self._credentials: dns_common.CredentialsConfiguration

    @property
    @abc.abstractmethod
    def _provider_name(self) -> str:
        """
        The name of the Lexicon provider to use
        """

    @property
    def _ttl(self) -> int:
        """
        Time to live to apply to the DNS records created by this Authenticator
        """
        return 60

    def _add_provider_option(self, creds_var_name: str, creds_var_label: str,
                             lexicon_provider_option_name: str) -> None:
        self._provider_options.append(
            (creds_var_name, creds_var_label, lexicon_provider_option_name))

    def _build_lexicon_config(self, domain: str) -> ConfigResolver:
        if not hasattr(self, '_credentials'):  # pragma: no cover
            self._setup_credentials()

        dict_config = {
            'domain': domain,
            'provider_name': self._provider_name,
            'ttl': self._ttl,
            self._provider_name: {item[2]: self._credentials.conf(item[0])
                                  for item in self._provider_options}
        }
        return ConfigResolver().with_dict(dict_config).with_env()

    def _setup_credentials(self) -> None:
        self._credentials = self._configure_credentials(
            key='credentials',
            label=f'Credentials INI file for {self._provider_name} DNS authenticator',
            required_variables={item[0]: item[1] for item in self._provider_options},
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        resolved_domain = self._resolve_domain(domain)

        try:
            with Client(self._build_lexicon_config(resolved_domain)) as operations:
                operations.create_record(rtype='TXT', name=validation_name, content=validation)
        except RequestException as e:
            logger.debug('Encountered error adding TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error adding TXT record: {0}'.format(e))

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        try:
            resolved_domain = self._resolve_domain(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding domain_id during deletion: %s', e,
                         exc_info=True)
            return

        try:
            with Client(self._build_lexicon_config(resolved_domain)) as operations:
                operations.delete_record(rtype='TXT', name=validation_name, content=validation)
        except RequestException as e:
            logger.debug('Encountered error deleting TXT record: %s', e, exc_info=True)

    def _resolve_domain(self, domain: str) -> str:
        domain_name_guesses = dns_common.base_domain_name_guesses(domain)

        for domain_name in domain_name_guesses:
            try:
                with Client(self._build_lexicon_config(domain_name)):
                    return domain_name
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


# This class takes a similar approach to the cryptography project to deprecate attributes
# in public modules. See the _ModuleWithDeprecation class here:
# https://github.com/pyca/cryptography/blob/91105952739442a74582d3e62b3d2111365b0dc7/src/cryptography/utils.py#L129
class _DeprecationModule:
    """
    Internal class delegating to a module, and displaying warnings when attributes
    related to deprecated attributes in the current module.
    """
    def __init__(self, module: ModuleType):
        self.__dict__['_module'] = module

    def __getattr__(self, attr: str) -> Any:
        if attr in ('LexiconClient', 'build_lexicon_config'):
            warnings.warn(f'{attr} attribute in {__name__} module is deprecated '
                          'and will be removed soon.',
                          DeprecationWarning, stacklevel=2)
        return getattr(self._module, attr)

    def __setattr__(self, attr: str, value: Any) -> None:  # pragma: no cover
        setattr(self._module, attr, value)

    def __delattr__(self, attr: str) -> Any:  # pragma: no cover
        delattr(self._module, attr)

    def __dir__(self) -> List[str]:  # pragma: no cover
        return ['_module'] + dir(self._module)


# Patching ourselves to warn about deprecation and planned removal of some elements in the module.
sys.modules[__name__] = cast(ModuleType, _DeprecationModule(sys.modules[__name__]))
