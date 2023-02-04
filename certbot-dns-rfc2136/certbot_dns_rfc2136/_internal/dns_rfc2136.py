"""DNS Authenticator using RFC 2136 Dynamic Updates."""
import logging
import time
from typing import Any
from typing import Callable
from typing import Dict
from typing import Optional
from typing import Tuple
from typing import Union
import uuid

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TKEY
import dns.tsig
import dns.tsigkeyring
import dns.update

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration
from certbot.util import is_ipaddress

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_TIMEOUT = 45

KeyringType = Union[Dict[dns.name.Name, bytes], dns.tsig.GSSTSigAdapter]


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator using RFC 2136 Dynamic Updates

    This Authenticator uses RFC 2136 Dynamic Updates to fulfill a dns-01 challenge.
    """

    ALGORITHMS = {
      'GSS-TSIG': dns.tsig.GSS_TSIG,
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
        super().add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='RFC 2136 credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'RFC 2136 Dynamic Updates.'

    def _validate_credentials(self, credentials: CredentialsConfiguration) -> None:
        server = credentials.conf('server')
        if not is_ipaddress(server):
            raise errors.PluginError("The configured target DNS server ({0}) is not a valid IPv4 "
                                     "or IPv6 address. A hostname is not allowed.".format(server))
        algorithm = credentials.conf('algorithm')
        if algorithm:
            if not self.ALGORITHMS.get(algorithm.upper()):
                raise errors.PluginError("Unknown algorithm: {0}.".format(algorithm))

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'RFC 2136 credentials INI file',
            {
                'name': 'TSIG key name (for HMAC) or server name (for GSS-TSIG)',
                'secret': 'TSIG key secret (for HMAC) or credential parameters (for GSS_TSIG)',
                'server': 'IP address of the target DNS server'
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
        return _RFC2136Client(self.credentials.conf('server'),
                              int(self.credentials.conf('port') or self.PORT),
                              self.credentials.conf('name'),
                              self.credentials.conf('secret'),
                              self.ALGORITHMS.get(self.credentials.conf('algorithm'),
                                                  dns.tsig.HMAC_MD5))


class _RFC2136Client:
    """
    Encapsulates all communication with the target DNS server.
    """

    keyring: KeyringType
    keyname: dns.name.Name

    def __init__(self, server: str, port: int, key_name: str, key_secret: str,
                 key_algorithm: dns.name.Name, timeout: int = DEFAULT_NETWORK_TIMEOUT) -> None:
        self.server = server
        self.port = port
        self.algorithm = key_algorithm
        self._default_timeout = timeout
        if self.algorithm == dns.tsig.GSS_TSIG:
            # For GSS-TSIG we expect 'key_name' to contain the server's FQDN, which is mandatory to
            # obtain Kerberos tickets for that server (somewhat similar to validating TLS hostname).
            self.keyring, self.keyname = self._negotiate_gss_keyring(key_name, key_secret)
        else:
            self.keyring = dns.tsigkeyring.from_text({key_name: key_secret})
            self.keyname = dns.name.from_text(key_name)

    def _build_tkey_query(self, token, key_ring: dns.tsig.GSSTSigAdapter,
                          key_name: dns.name.Name) -> dns.message.QueryMessage:
        inception_time = int(time.time())
        tkey = dns.rdtypes.ANY.TKEY.TKEY(dns.rdataclass.ANY,
                                         dns.rdatatype.TKEY,
                                         dns.tsig.GSS_TSIG,
                                         inception_time,
                                         inception_time,
                                         3,
                                         dns.rcode.NOERROR,
                                         token,
                                         b'')
        query = dns.message.make_query(key_name,
                                       dns.rdatatype.TKEY,
                                       dns.rdataclass.ANY)
        query.keyring = key_ring
        query.find_rrset(dns.message.ADDITIONAL,
                         key_name,
                         dns.rdataclass.ANY,
                         dns.rdatatype.TKEY,
                         create=True).add(tkey)
        return query

    def _negotiate_gss_keyring(self, server_name: str,
                               key_secret: str) -> Tuple[dns.tsig.GSSTSigAdapter, dns.name.Name]:
        import gssapi

        # By default GSSAPI will take credentials from environment (KRB5CCNAME for the ticket cache
        # and optionally KRB5_CLIENT_KTNAME for a keytab to automatically acquire tickets with),
        # but recent MIT Krb5 allows specifying this per-context using "credential store extensions"
        # which we use if "ccache=" and/or "client_keytab=" parameters are specified, e.g.
        #
        # dns_rfc2136_secret = ccache=FILE:/tmp/krb5cc_certbot client_keytab=FILE:/etc/krb5.keytab
        if key_secret and key_secret != 'None':
            cred_params = {}
            for kvp in key_secret.split():
                k, v = kvp.split('=', 1)
                cred_params[k] = v
            gss_cred = gssapi.Credentials(usage='initiate', store=cred_params)
        else:
            gss_cred = None

        # Initialize GSSAPI context
        gss_name = gssapi.Name('DNS@{0}'.format(server_name), gssapi.NameType.hostbased_service)
        #gss_ctx = gssapi.SecurityContext(name=gss_name, usage='initiate')
        gss_ctx = gssapi.SecurityContext(name=gss_name, creds=gss_cred, usage='initiate')

        # Name generation tips: https://tools.ietf.org/html/rfc2930#section-2.1
        key_name = dns.name.from_text('{0}.{1}'.format(uuid.uuid4(), server_name))
        tsig_key = dns.tsig.Key(key_name, gss_ctx, dns.tsig.GSS_TSIG)
        key_ring = dns.tsig.GSSTSigAdapter({key_name: tsig_key})

        # Perform GSSAPI negotiation via TKEY
        in_token = None
        while not gss_ctx.complete:
            out_token = gss_ctx.step(in_token)
            if not out_token:
                break
            request = self._build_tkey_query(out_token, key_ring, key_name)
            try:
                response = dns.query.tcp(request, self.server, self._default_timeout, self.port)
            except (OSError, dns.exception.Timeout) as e:
                logger.debug('TCP query failed, fallback to UDP: %s', e)
                response = dns.query.udp(request, self.server, self._default_timeout, self.port)
            in_token = response.answer[0][0].key

        return key_ring, key_name

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

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyname=self.keyname,
            keyalgorithm=self.algorithm)
        update.add(rel, record_ttl, dns.rdatatype.TXT, record_content)

        try:
            response = dns.query.tcp(update, self.server, self._default_timeout, self.port)
        except Exception as e:
            raise errors.PluginError('Encountered error adding TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()  # type: ignore[attr-defined]

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

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyname=self.keyname,
            keyalgorithm=self.algorithm)
        update.delete(rel, dns.rdatatype.TXT, record_content)

        try:
            response = dns.query.tcp(update, self.server, self._default_timeout, self.port)
        except Exception as e:
            raise errors.PluginError('Encountered error deleting TXT record: {0}'
                                     .format(e))
        rcode = response.rcode()  # type: ignore[attr-defined]

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
        # Use our TSIG keyring
        request.use_tsig(self.keyring, self.keyname,
                         algorithm=self.algorithm) # type: ignore[attr-defined]

        try:
            try:
                response = dns.query.tcp(request, self.server, self._default_timeout, self.port)
            except (OSError, dns.exception.Timeout) as e:
                logger.debug('TCP query failed, fallback to UDP: %s', e)
                response = dns.query.udp(request, self.server, self._default_timeout, self.port)
            rcode = response.rcode()  # type: ignore[attr-defined]

            # Authoritative Answer bit should be set
            if (rcode == dns.rcode.NOERROR
                    and response.get_rrset(response.answer,  # type: ignore[attr-defined]
                                           domain, dns.rdataclass.IN, dns.rdatatype.SOA)
                    and response.flags & dns.flags.AA):
                logger.debug('Received authoritative SOA response for %s', domain_name)
                return True

            logger.debug('No authoritative SOA record found for %s', domain_name)
            return False
        except Exception as e:
            raise errors.PluginError('Encountered error when making query: {0}'
                                     .format(e))
