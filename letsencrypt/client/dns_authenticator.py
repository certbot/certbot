"""DNS Authenticator"""
import dns.query
import dns.rcode
import dns.resolver
import dns.tsigkeyring
import dns.update

import zope.interface

from letsencrypt.acme import challenges

from letsencrypt.client import constants
from letsencrypt.client import errors
from letsencrypt.client import interfaces


def find_valid_key(tsig_keys, domain):
    """Search provided TSIG key pairs.

    Search the keypairs provided on the CLI for one valid for the
    provided `domain`.

    :param list tsig_keys: List of tuples containing key name, key secret,
        and domains key is valid for.
    :param str domain: Domain name to look for a key pair for.

    :returns: Keyring valid for `domain` or `None`.
    :rtype: dns.tsigkeyring

    """
    for keypair in tsig_keys:
        if domain in keypair[2]:
            return dns.tsigkeyring.from_text({keypair[0]: keypair[1]})

def add_record(zone, token, keyring):
    """Add record DNS request generator.

    Create a `dns.message.Message` object asking the server to
    create a TXT record for the challenge subdomain
    (`_acme-challenge.example.com`) signed by the provided
    TSIG keyring.

    :param str zone: Zone (domain) in which the record should
        be provisioned.
    :param str token: Token provided by ACME server.
    :param dns.tsigkeyring keyring: TSIG keyring object containg TSIG
        key pair valid for the provided zone.

    :returns: Add record DNS message.
    :rtype: dns.message.Message

    """
    challenge_request = dns.update.Update(zone, keyring=keyring)
    # check challenge_subdomain is absent
    challenge_request.absent(constants.DNS_CHALLENGE_SUBDOMAIN)
    # add challenge_subdomain TXT with token
    challenge_request.add(constants.DNS_CHALLENGE_SUBDOMAIN,
                          constants.DNS_CHALLENGE_TTL, "TXT", token)

    # return req
    return challenge_request

def del_record(zone, token, keyring): # pylint: disable=unused-argument
    """Delete record DNS request generator.

    Create a `dns.message.Message` object asking the server to
    delete a TXT record for the challenge subdomain
    (`_acme-challenge.example.com`) signed by the provided
    TSIG keyring.

    :param str zone: Zone (domain) in which the record should exists.
    :param str token: Not needed
    :param dns.tsigkeyring keyring: TSIG keyring object containg TSIG
        keypair valid for the provided zone.

    :returns: Delete record DNS message.
    :rtype: dns.message.Message

    """
    challenge_request = dns.update.Update(zone, keyring=keyring)
    # check challenge_subdomain is present
    challenge_request.present(constants.DNS_CHALLENGE_SUBDOMAIN)
    # delete challegen_subdomain TXT
    challenge_request.delete(constants.DNS_CHALLENGE_SUBDOMAIN)

    # return req
    return challenge_request

def send_request(gen_request, zone, token, keyring, server, port):
    """Generate and send request to DNS server.

    Generates a DNS message based on function passed as `gen_request`
    (either :meth:`add_record` or :meth:`del_record`) and then sends it to
    the DNS server specified by `server` at `port`. If the DNS request fails
    for any reason `LetsEncryptDNSAuthError` willbe raised, otherwise `True`
    will be returned.

    :param function gen_request: Function (either :meth:`add_record` or
        :meth:`del_record`) used to generate the relevant DNS message.
    :param str zone: Zone (domain) in which things will happen.
    :param str token: Token provided by ACME server.
    :param dns.tsigkeyring keyring: TSIG keyring object containg TSIG
        keypair valid for the provided zone.
    :param str server: Hostname or IP address of DNS server to make
        requests to.
    :param int port: Port the DNS server listens on.

    :returns: `True` if challenge subdomain is successfully
        provisioned.
    :rtype: bool

    """
    dns_request = gen_request(zone, token, keyring)

    # FIXME: better keyring errors (that include that key that was used)
    rcode_errors = {
        dns.rcode.FORMERR: 'Malformed DNS message',
        dns.rcode.SERVFAIL: 'Server failed',
        dns.rcode.NXDOMAIN: 'Domain does not exist on DNS server'
                            ' (%s)' % (zone),
        dns.rcode.NOTIMP: 'DNS server does not support that opcode',
        dns.rcode.REFUSED: ('DNS server refuses to perform the specified '
                            'operation for policy or security reasons'),
        dns.rcode.YXDOMAIN: ('Name exists when it should not (%s.%s)'
                             % (constants.DNS_CHALLENGE_SUBDOMAIN, zone)),
        dns.rcode.YXRRSET: ('Records that should not exist do exist (%s.%s)'
                            % (constants.DNS_CHALLENGE_SUBDOMAIN, zone)),
        dns.rcode.NXRRSET: ('Records that should exist do not exist (%s.%s)'
                            % (constants.DNS_CHALLENGE_SUBDOMAIN, zone)),
        dns.rcode.NOTAUTH: ('Server is not authorized or was supplied bad TSIG'
                            ' key to make updates to zone "%s" [key: %s]'
                            % (zone, dns.tsigkeyring.to_text(keyring))),
        dns.rcode.NOTZONE: ('Zone "%s" does not exist' % (zone)),
        # this rcode can also mean BADOPT (Bad OPT version)
        dns.rcode.BADVERS: ('Server was supplied bad TSIG key to '
                            'make updates to zone "%s" [key: %s]'
                            % (zone, dns.tsigkeyring.to_text(keyring))),
        # this rcode isn't specified in dnspython but means BADKEY
        17: ('Server was supplied bad TSIG key to make updates to zone'
             ' "%s"  [key: %s]' % (zone, dns.tsigkeyring.to_text(keyring))),
        }

    try:
        resp = dns.query.tcp(dns_request, server, port=port,
                             source_port=constants.DNS_CHALLENGE_SOURCE_PORT,
                             timeout=constants.DNS_CHALLENGE_TIMEOUT)

        if resp.rcode() == 0:
            return True
        else:
            raise errors.LetsEncryptDNSAuthError(
                "DNS Error: %s" % (rcode_errors.get(resp.rcode())))

    except (dns.resolver.NoAnswer, dns.query.UnexpectedSource,
            dns.query.BadResponse, OSError) as err:
        # elif isinstance(err, TimeoutError):
        #     dns_error = "DNS Error: DNS request timed out!"
        if isinstance(err, dns.resolver.NoAnswer):
            dns_error = "DNS Error: Did not recieve a response to DNS request!"
        elif isinstance(err, dns.query.UnexpectedSource):
            dns_error = ("DNS Error: Recieved response to DNS request from "
                         "unexpected source!")
        elif isinstance(err, dns.query.BadResponse):
            dns_error = ("DNS Error: Recieved malformed response to DNS "
                         "request!")
        elif isinstance(err, OSError):
            dns_error = ("DNS Error: I forgot what an OSError means in this"
                         " context...")
        raise errors.LetsEncryptDNSAuthError(dns_error)

class DNSAuthenticator(object):
    """DNS Authenticator

    This authenticator interacts with an already configured DNS
    server in order to provision subdomains in response to DNS
    challenges from the certificate authority.

    """
    zope.interface.implements(interfaces.IAuthenticator)

    def __init__(self, config):
        # super(DNSAuthenticator, self).__init__(config)
        self.dns_server = config.dns_server
        self.dns_server_port = config.dns_server_port
        self.dns_tsig_keys = config.dns_tsig_keys

        if self.dns_tsig_keys is None:
            raise errors.LetsEncryptDNSAuthError("No TSIG keys provided.")

    @staticmethod
    def get_chall_pref(unused_domain):
        """Get challenge preferences.

        :returns: A list containing only 'challenges.DNS'.

        """
        return [challenges.DNS]

    def perform(self, achalls):
        """Perform the challenges."""
        responses = []
        for achall in achalls:
            zone = achall.domain
            token = achall.token
            tsig_keyring = find_valid_key(self.dns_tsig_keys, zone)
            if not tsig_keyring:
                raise errors.LetsEncryptDNSAuthError("No TSIG keypair provided"
                                                     " for %s" % (zone))

            # send request
            if send_request(add_record, zone, token, tsig_keyring,
                            self.dns_server, self.dns_server_port):
                responses.append(challenges.DNSResponse())
        return responses

    def cleanup(self, achalls):
        """Clean up, remove all challenge subdomains that were provisioned."""
        for achall in achalls:
            zone = achall.domain
            token = achall.token
            tsig_keyring = find_valid_key(self.dns_tsig_keys, zone)
            if not tsig_keyring:
                raise errors.LetsEncryptDNSAuthError("No TSIG keypair provided"
                                                     " for %s" % (zone))

            # send it, raises error on absent records etc...
            send_request(del_record, zone, token, tsig_keyring,
                         self.dns_server, self.dns_server_port)
