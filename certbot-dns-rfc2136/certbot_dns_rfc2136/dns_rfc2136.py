"""DNS Authenticator using RFC 2136 Dynamic Updates."""
import logging

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator using RFC 2136 Dynamic Updates

    This Authenticator uses RFC 2136 Dynamic Updates to fulfull a dns-01 challenge.
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

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='RFC 2136 credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RFC 2136 Dynamic Updates.'

    def _validate_algorithm(self, credentials):
        algorithm = credentials.conf('algorithm')
        if algorithm:
            if not self.ALGORITHMS.get(algorithm.upper()):
                raise errors.PluginError("Unknown algorithm: {0}.".format(algorithm))

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'RFC 2136 credentials INI file',
            {
                'name': 'TSIG key name',
                'secret': 'TSIG key secret',
                'server': 'The target DNS server'
            },
            self._validate_algorithm
        )

    def _perform(self, _domain, validation_name, validation):
        self._get_rfc2136_client().add_txt_record(validation_name, validation, self.ttl)

    def _cleanup(self, _domain, validation_name, validation):
        self._get_rfc2136_client().del_txt_record(validation_name, validation)

    def _get_rfc2136_client(self):
        key = _RFC2136Key(self.credentials.conf('name'),
                          self.credentials.conf('secret'),
                          self.ALGORITHMS.get(self.credentials.conf('algorithm'),
                                              dns.tsig.HMAC_MD5))
        return _RFC2136Client(self.credentials.conf('server'),
                              int(self.credentials.conf('port') or self.PORT),
                              key,
                              self.credentials.conf('base-domain'))

class _RFC2136Key(object):
    def __init__(self, name, secret, algorithm):
        self.name = name
        self.secret = secret
        self.algorithm = algorithm

class _RFC2136Client(object):
    """
    Encapsulates all communication with the target DNS server.
    """
    def __init__(self, server, port, key, base_domain):
        self.server = server
        self.port = port
        self.keyring = dns.tsigkeyring.from_text({
            key.name: key.secret
        })
        self.algorithm = key.algorithm
        self.base_domain = base_domain

    def add_txt_record(self, record_name, record_content, record_ttl):
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

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.add(rel, record_ttl, dns.rdatatype.TXT, record_content)

        try:
            response = dns.query.tcp(update, self.server, port=self.port)
        except Exception as e:
            raise errors.PluginError('Encountered error adding TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully added TXT record')
        else:
            raise errors.PluginError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def del_txt_record(self, record_name, record_content):
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

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.delete(rel, dns.rdatatype.TXT, record_content)

        try:
            response = dns.query.tcp(update, self.server, port=self.port)
        except Exception as e:
            raise errors.PluginError('Encountered error deleting TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully deleted TXT record')
        else:
            raise errors.PluginError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def _find_domain(self, record_name):
        """
        If 'base_domain' option is specified check if the requested domain matches this base domain
        and return it. If not explicitly specified find the closest domain with an SOA record for
        the given domain name.

        :param str record_name: The record name for which to find the base domain.
        :returns: The domain, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no SOA record can be found.
        """

        if self.base_domain:
            if not record_name.endswith(self.base_domain):
                raise errors.PluginError('Requested domain {0} does not match specified base '
                                         'domain {1}.'
                                         .format(record_name, self.base_domain))
            else:
                return self.base_domain
        else:
            domain_name_guesses = dns_common.base_domain_name_guesses(record_name)

            # Loop through until we find an authoritative SOA record
            for guess in domain_name_guesses:
                if self._query_soa(guess):
                    return guess

            raise errors.PluginError('Unable to determine base domain for {0} using names: {1}.'
                                     .format(record_name, domain_name_guesses))

    def _query_soa(self, domain_name):
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

        try:
            response = dns.query.udp(request, self.server, port=self.port)
            rcode = response.rcode()

            # Authoritative Answer bit should be set
            if (rcode == dns.rcode.NOERROR and response.get_rrset(response.answer,
                domain, dns.rdataclass.IN, dns.rdatatype.SOA) and response.flags & dns.flags.AA):
                logger.debug('Received authoritative SOA response for %s', domain_name)
                return True

            logger.debug('No authoritative SOA record found for %s', domain_name)
            return False
        except Exception as e:
            raise errors.PluginError('Encountered error when making query: {0}'
                                     .format(e))
