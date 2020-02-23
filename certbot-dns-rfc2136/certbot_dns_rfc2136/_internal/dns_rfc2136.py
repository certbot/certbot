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

from acme.magic_typing import Dict, Tuple, List  # pylint: disable=unused-import, no-name-in-module

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

    def more_info(self):  # pylint: disable=missing-function-docstring
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
        return _RFC2136Client(self.credentials.conf('server'),
                              int(self.credentials.conf('port') or self.PORT),
                              self.credentials.conf('name'),
                              self.credentials.conf('secret'),
                              self.ALGORITHMS.get(self.credentials.conf('algorithm'),
                                                  dns.tsig.HMAC_MD5))


class _RFC2136Client(object):
    """
    Encapsulates all communication with the target DNS server.
    """
    def __init__(self, server, port, key_name, key_secret, key_algorithm):
        self.server = server
        self.port = port
        self.keyring = dns.tsigkeyring.from_text({
            key_name: key_secret
        })
        self.algorithm = key_algorithm

    def add_txt_record(self, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        logger.debug('Adding TXT record: %s %d "%s"', record_name, record_ttl, record_content)

        (rel, domain) = self._find_domain(record_name)

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
            logger.debug('Successfully added TXT record %s', record_name)
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

        (rel, domain) = self._find_domain(record_name)

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
            logger.debug('Successfully deleted TXT record %s', record_name)
        else:
            raise errors.PluginError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def _find_domain(self, record_name):
        """
        Find the closest domain with an SOA record for a given domain name.

        :param str record_name: The record name for which to find the closest SOA record.
        :returns: tuple of (`entry`, `zone`) where
                `entry` - canonical relative entry into the target zone;
                `zone` - canonical absolute name of the zone to be modified.
        :rtype: (`dns.name.Name`, `dns.name.Name`)
        :raises certbot.errors.PluginError: if the search failed for any reason.
        """

        # Note: an absolute dns.name.Name ends in dns.name.root, which
        # is non-empty. Therefore the first prefix.split(1) splits off
        # dns.name.root, i.e. example.com. -> (example.com, .), not
        # example.com. -> (example, com.).  dns.name.empty, however,
        # is an actual empty name, has a truth value of False, and is
        # an identity element for the append operation; thus
        # dns.name.root + dns.name.empty == dns.name.root.
        #
        # This code relies on these properties.

        domain = dns.name.from_text(record_name)
        prefix = domain
        suffix = dns.name.empty
        found = None
        domstr = str(domain)    # For messages, may have a DNAME/CNAME added

        # The domains already queried and the corresponding results
        domain_names_searched = dict()  # type: Dict[str, Tuple[bool, dns.rdata.Rdata]]

        while prefix:
            (prefix, next_label) = prefix.split(1)
            suffix = next_label + suffix

            # Don't re-query if we have already been here (normal
            # during DNAME/CNAME re-walk)
            if suffix in domain_names_searched:
                result = domain_names_searched[suffix]
            else:
                result = self._query_soa(suffix)
                domain_names_searched[suffix] = result

            (auth, rr) = result
            if rr is None:
                # Nothing to do, just descend the DNS hierarchy
                pass
            elif rr.rdtype == dns.rdatatype.SOA:
                # We found an SOA, authoritative or not
                found = (auth, prefix, suffix)
            else:
                # We found a DNAME or CNAME. We need to start the walk over
                # from the common point of departure.
                target = rr.target
                if target in domain_names_searched:
                    # DNAME/CNAME loop!
                    errors.PluginError('{0} {1} loops seeking SOA for {2}'
                                       .format(suffix, repr(rr), domstr))

                # Restart from the root, replacing the current suffix
                prefix = prefix + target
                suffix = dns.name.empty
                found = None
                domstr = str(domain)+' ('+str(prefix)+')'  # For messages

        if not found:
            raise errors.PluginError('No SOA of any kind found for {0}'.format(domstr))

        (auth, prefix, suffix) = found
        if not auth:
            raise errors.PluginError('SOA {0} for {1} not authoritative'.format(suffix, domstr))
        return prefix, suffix

    def _query_soa(self, domain):
        """
        Query a domain name for an authoritative SOA record.

        :param dns.name.Name domain: The domain name to query for an SOA record.
        :returns: (`authoritative`, `rdata`) if found
                autoritative bool if response was authoritative
                rdata dns.rdata.Rdata or None the returned record
        :rtype: (`bool`, `dns.rdata.Rdata` or `None`)
        :raises certbot.errors.PluginError: if no response is received.
        """

        # In order to capture any possible CNAMEs, we have to do the
        # search upward from the root. On the way, any time we find a
        # SOA record, save it; the final SOA record captured is the
        # target. If that SOA record is not authoritative, then
        # we have a fatal error.
        #
        # As we want to know about either type, we request recursion
        # from the target name server. If the target nameserver does
        # not provide recursion services, it will still work for
        # finding an authoritative SOA, DNAME or CNAME record
        # in a zone for which the nameserver is authoritarive; this is
        # expected to be the common case, although it is not 100%
        # guaranteed. The only ways to avoid that, ultimately, is to use
        # a trusted recursive nameserver instead if we get a !RA response
        # (e.g. using dns.resolver?) or actually query the authoritative name
        # servers all the way from the top.
        #
        # We intentionally only look in the answer section, not in
        # the authority or additional sections, and only for records
        # which match the requested domain name exactly.
        #
        # If we get more than one SOA, DNAME, or CNAME record of the
        # same type and exactly matching the requested domain in the
        # *answer* section we are really in an error situation (these
        # are all singleton RRs), but try to make the best of the
        # situation.

        request = dns.message.make_query(domain, dns.rdatatype.SOA, dns.rdataclass.IN)

        try:
            logmsg = 'Query '+str(domain)
            try:
                response = dns.query.tcp(request, self.server, port=self.port)
            except OSError as e:
                logger.debug('TCP query failed, fallback to UDP: %s', e)
                response = dns.query.udp(request, self.server, port=self.port)
            rcode = response.rcode()
            logmsg += ': '+dns.rcode.to_text(rcode)

            auth = (response.flags & dns.flags.AA) != 0
            if auth:
                logmsg += ', authoritative'
            else:
                logmsg += ', non-authoritative'

            found = dict()  # type: Dict[int, List[dns.rdataset.Rdata]]
            for rrset in response.answer:
                if rrset.name != domain:
                    continue
                if rrset.rdclass != dns.rdataclass.IN:
                    continue
                for rr in rrset:
                    if not rr.rdtype in found:
                        found[rr.rdtype] = [rr]
                    elif not rr in found[rr.rdtype]:
                        # Explicitly ignore exact duplicate RRs
                        found[rr.rdtype].append(rr)

            for rdtype in found:
                logmsg += ' %s %d' % (dns.rdatatype.to_text(rdtype), len(found[rdtype]))

            retrr = None
            for rdtype in dns.rdatatype.SOA, dns.rdatatype.DNAME, dns.rdatatype.CNAME:
                if rdtype in found:
                    retrr = found[rdtype][0]    # Use the first one returned
                    break

            logmsg += ', returning '+repr(retrr)
            logger.debug(logmsg)
            return auth, retrr

        except Exception as e:
            raise errors.PluginError('Encountered error when making query: {0}'.format(e))
