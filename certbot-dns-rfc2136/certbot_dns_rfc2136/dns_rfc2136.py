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

    description = 'Obtain certs using a DNS TXT record (if you are using BIND for DNS).'
    ttl = 120

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='RFC 2136 credentials INI file.')

    def more_info(self):
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RFC 2136 Dynamic Updates.'

    def _setup_credentials(self):
        self.credetials = self._configure_credentials(
            'credentials',
            'RFC 2136 credentials INI file',
            {
                'name': 'TSIG key name',
                'secret': 'TSIG key secret',
                'algorithm': 'TSIG key algorithm',
                'server': 'The target DNS server'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_rfc2136_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_rfc2136_client().del_txt_record(domain, validation_name, validation)

    def _get_rfc2136_client(self):
        return _RFC2136Client(self.credentials.conf('server'), self.credentials.conf('name'), self.credentials.conf('secret'), self.credentials.conf('algorithm'))


class _RFC2136Client(object):
    """
    """

    ALGORITHMS = {
      'HMAC-MD5': dns.tsig.HMAC_MD5,
      'HMAC-SHA1': dns.tsig.HMAC_SHA1,
      'HMAC-SHA224': dns.tsig.HMAC_SHA224,
      'HMAC-SHA256': dns.tsig.HMAC_SHA256,
      'HMAC-SHA384': dns.tsig.HMAC_SHA384,
      'HMAC-SHA512': dns.tsig.HMAC_SHA512
    }

    def __init__(self, server, key_name, key_secret, key_algorithm='HMAC-MD5'):
        self.server = server
        self.keyring = dns.tsigkeyring.from_text({
            key_name: key_secret
        })
        self.algorithm = self.ALGORITHMS.get(key_algorithm, dns.tsig.HMAC_MD5)

    def add_txt_record(self, domain_name, record_name, record_content, record_ttl):
        """
        """

        domain = self._find_domain(domain_name)

        n = dns.name.from_text(record_name)
        o = dns.name.from_text(domain)
        rel = n.relativize(o)

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.add(rel, record_ttl, dns.rdatatype.TXT, record_content)

        try:
            response = dns.query.tcp(update, self.server)

            logger.debug('Successfully added TXT record')
        except dns.exception.DNSException as e:
            raise errors.PluginError('')

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        """

        domain = self._find_domain(domain_name)

        n = dns.name.from_text(record_name)
        o = dns.name.from_text(domain)
        rel = n.relativize(o)

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.delete(rel, dns.rdatatype.TXT, record_content)

        try:
            response = dns.query.tcp(update, self.server)

            logger.debug('Successfully removed TXT record')
        except dns.exception.DNSException as e:
            raise errors.PluginError('')

    def _find_domain(self, domain_name):
        """
        """

        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        # Loop through until we find an authoritative SOA record
        for guess in domain_name_guesses:
            domain = dns.name.from_text(guess)
            if not domain.is_absolute():
                domain = domain.concatenate(dns.name.root)

            request = dns.message.make_query(domain, dns.rdatatype.SOA, dns.rdataclass.IN)
            # Turn off Recursion Desired bit in query
            request.flags ^= dns.flags.RD

            try:
                response = dns.query.tcp(request, self.server)
                rcode = response.rcode()
                # Authoritative Answer bit should be set
                if rcode == dns.rcode.NOERROR and response.flags & dns.flags.AA:
                    return guess
            except dns.exception.DNSException as e:
                pass
