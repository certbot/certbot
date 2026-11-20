"""DNS Authenticator using RFC 2136 Dynamic Updates."""
from enum import Enum
import logging
from typing import Any
from typing import Callable
from typing import cast
from typing import Optional

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration
from certbot.util import is_ipaddress

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_TIMEOUT = 45

class ProtoPref(Enum):
    """Enum for protocol preference options."""

    TCP_ONLY  = 'tcp_only'
    TCP_FIRST = 'tcp_first'
    UDP_ONLY  = 'udp_only'
    UDP_FIRST = 'udp_first'

    @classmethod
    def map_to_func_list(cls, pp: 'ProtoPref') -> list[Callable[..., dns.message.Message]]:
        """Map protocol preference to list of dns.query functions."""
        return {
            ProtoPref.TCP_ONLY: [dns.query.tcp],
            ProtoPref.TCP_FIRST: [dns.query.tcp, dns.query.udp],
            ProtoPref.UDP_ONLY: [dns.query.udp],
            ProtoPref.UDP_FIRST: [dns.query.udp, dns.query.tcp]
        }[pp] # type: ignore

class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator using RFC 2136 Dynamic Updates

    This Authenticator uses RFC 2136 Dynamic Updates to fulfill a dns-01 challenge.
    """

    ALGORITHMS = {
      'HMAC-MD5': dns.tsig.HMAC_MD5,
      'HMAC-SHA1': dns.tsig.HMAC_SHA1,
      'HMAC-SHA224': dns.tsig.HMAC_SHA224,
      'HMAC-SHA256': dns.tsig.HMAC_SHA256,
      'HMAC-SHA384': dns.tsig.HMAC_SHA384,
      'HMAC-SHA512': dns.tsig.HMAC_SHA512
    }

    PORT = 53

    description = 'Obtain certificates using a DNS TXT record (if you are using BIND for DNS).'
    ttl = 120

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='RFC 2136 credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RFC 2136 Dynamic Updates.'

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        server = cast(str, credentials.conf('server'))
        if not is_ipaddress(server):
            raise errors.PluginError("The configured target DNS server ({0}) is not a valid IPv4 "
                                     "or IPv6 address. A hostname is not allowed.".format(server))
        algorithm = credentials.conf('algorithm')
        if algorithm:
            if not self.ALGORITHMS.get(algorithm.upper()):
                raise errors.PluginError("Unknown algorithm: {0}.".format(algorithm))
        server_pp = cast(str, credentials.conf('server_proto_pref'))
        if server_pp and server_pp.upper() not in ProtoPref.__members__:
            raise errors.PluginError("Unknown protocol preference: {0}. Must be one of {1}."
                        .format(server_pp, str.join(', ', sorted(ProtoPref.__members__))))
        update_server = cast(str, credentials.conf('update_server'))
        if update_server and not is_ipaddress(update_server):
            raise errors.PluginError(f"The configured target update server ({update_server})" + \
                                "is not a valid IPv4 or IPv6 address. A hostname is not allowed.")
        update_server_pp = cast(str, credentials.conf('update_server_proto_pref'))
        if update_server_pp and update_server_pp.upper() not in ProtoPref.__members__:
            raise errors.PluginError("Unknown update server protocol: {0}. Must be one of {1}."
                        .format(update_server_pp, str.join(', ',sorted(ProtoPref.__members__))))

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'RFC 2136 credentials INI file',
            {
                'name': 'TSIG key name',
                'secret': 'TSIG key secret',
                'server': 'The target DNS server'
            },
            self._validate_credentials
        )

    def _perform(self, _domain: str, validation_name: str, validation: str) -> None:
        self._get_rfc2136_client().add_txt_record(validation_name, validation, self.ttl)

    def _cleanup(self, _domain: str, validation_name: str, validation: str) -> None:
        self._get_rfc2136_client().del_txt_record(validation_name, validation)

    def _get_rfc2136_client(self) -> "_RFC2136Client":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")

        algorithm: str = (self.credentials.conf('algorithm') or '').upper()

        return _RFC2136Client(cast(str, self.credentials.conf('server')),
                              int(cast(str, self.credentials.conf('port')) or self.PORT),
                              cast(str, self.credentials.conf('name')),
                              cast(str, self.credentials.conf('secret')),
                              self.ALGORITHMS.get(algorithm, dns.tsig.HMAC_MD5),
                              (self.credentials.conf('sign_query') or '').upper() == "TRUE",
                              DEFAULT_NETWORK_TIMEOUT,
                              self.credentials.conf('server_proto_pref'),
                              self.credentials.conf('update_server'),
                              self.credentials.conf('update_server_proto_pref'))


class _RFC2136Client:

    domain_to_challenges_map: dict[str, list[str]] = {}

    """
    Encapsulates all communication with the target DNS and/or update server.
    """
    def __init__(self, server: str, port: int, key_name: str, key_secret: str,
                 key_algorithm: dns.name.Name, sign_query: bool,
                 timeout: int = DEFAULT_NETWORK_TIMEOUT,
                 server_proto_pref: str | None = None,
                 update_server: str | None = None,
                 update_server_proto_pref: str | None = None) -> None:
        self.server = server
        self.port = port
        self.keyring = dns.tsigkeyring.from_text({
            key_name: key_secret
        })
        self.algorithm = key_algorithm
        self.sign_query = sign_query
        self._default_timeout = timeout
        self.update_server = update_server or server
        self.server_proto_pref = server_proto_pref\
            and ProtoPref(server_proto_pref) or ProtoPref.TCP_FIRST
        self.update_server_proto_pref = update_server_proto_pref\
            and ProtoPref(update_server_proto_pref) or ProtoPref.TCP_ONLY

    def _try_with_protocols(self, func: Callable[..., dns.message.Message],
            proto_pref: ProtoPref) -> dns.message.Message:
        """
        Try to execute a function using a list of protocol functions, falling back on failure.

        :param func: The function to execute, taking a protocol function as its only argument.
        :param protocol_func_list: The list of protocol functions to try.
        :returns: The result of the function.
        :raises dns.exception.Timeout: if all protocol functions time out.
        """

        proto_funcs = ProtoPref.map_to_func_list(proto_pref)
        for idx, protof in enumerate(proto_funcs):
            try:
                return func(protof)
            except (OSError, dns.exception.Timeout) as e:
                if idx == len(proto_funcs) - 1:
                    raise e
                def prot_to_msg(prot: Callable[..., Any]) -> str:
                    return 'TCP' if prot is dns.query.tcp else 'UDP'
                exception_message = prot_to_msg(protof) + " query failed"
                if idx < len(proto_funcs) - 1:
                    exception_message += ", fallback to " + prot_to_msg(proto_funcs[idx + 1])
                logger.debug('%s: %s', exception_message, e)
        return dns.message.Message()  # pragma: no cover

    def add_txt_record(self, record_name: str, record_content: str, record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        domain = self._find_domain(record_name)

        n = dns.name.from_text(record_name)
        o = dns.name.from_text(domain)
        rel = n.relativize(o)

        _RFC2136Client.domain_to_challenges_map.setdefault(domain, []).insert(0, record_content)
        record_content_list = _RFC2136Client.domain_to_challenges_map[domain]

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.add(rel, record_ttl, dns.rdatatype.TXT, *record_content_list)

        try:
            response = self._try_with_protocols(lambda prot:
                prot(update, self.update_server, self._default_timeout, self.port),
                self.update_server_proto_pref)
        except Exception as e:
            raise errors.PluginError('Encountered error adding TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully added TXT record %s', record_name)
        else:
            raise errors.PluginError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def del_txt_record(self, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        domain = self._find_domain(record_name)

        n = dns.name.from_text(record_name)
        o = dns.name.from_text(domain)
        rel = n.relativize(o)

        _RFC2136Client.domain_to_challenges_map.pop(domain, None)

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.delete(rel, dns.rdatatype.TXT, record_content)

        try:
            response = self._try_with_protocols(lambda prot:
                prot(update, self.update_server, self._default_timeout, self.port),
                self.update_server_proto_pref)
        except Exception as e:
            raise errors.PluginError('Encountered error deleting TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully deleted TXT record %s', record_name)
        else:
            raise errors.PluginError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def _find_domain(self, record_name: str) -> str:
        """
        Find the closest domain with an SOA record for a given domain name.

        :param str record_name: The record name for which to find the closest SOA record.
        :returns: The domain, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no SOA record can be found.
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(record_name)

        # Loop through until we find an authoritative SOA record
        for guess in domain_name_guesses:
            if self._query_soa(guess):
                return guess

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(record_name, domain_name_guesses))

    def _query_soa(self, domain_name: str) -> bool:
        """
        Query a domain name for an authoritative SOA record.

        :param str domain_name: The domain name to query for an SOA record.
        :returns: True if found, False otherwise.
        :rtype: bool
        :raises certbot.errors.PluginError: if no response is received.
        """

        domain = dns.name.from_text(domain_name)

        request = dns.message.make_query(domain, dns.rdatatype.SOA, dns.rdataclass.IN)
        # Turn off Recursion Desired bit in query
        request.flags ^= dns.flags.RD
        # Use our TSIG keyring if configured
        if self.sign_query:
            request.use_tsig(self.keyring, algorithm=self.algorithm)

        try:
            response = self._try_with_protocols(lambda prot:
                prot(request, self.server, self._default_timeout, self.port),
                self.server_proto_pref)
            rcode = response.rcode()

            # Authoritative Answer bit should be set
            if (rcode == dns.rcode.NOERROR
                    and response.get_rrset(response.answer,
                                           domain, dns.rdataclass.IN, dns.rdatatype.SOA)
                    and response.flags & dns.flags.AA):
                logger.debug('Received authoritative SOA response for %s', domain_name)
                return True

            logger.debug('No authoritative SOA record found for %s', domain_name)
            return False
        except Exception as e:
            raise errors.PluginError('Encountered error when making query: {0}'
                                     .format(e))
