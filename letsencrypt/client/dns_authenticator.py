"""DNS Authenticator"""
import dns.query
import dns.tsigkeyring
import dns.update
from dns.query import UnexpectedSource, BadResponse
from dns.resolver import NoAnswer

import zope.interface

from letsencrypt.acme import challenges

from letsencrypt.client import achallenges
from letsencrypt.client import constants
from letsencrypt.client import errors
from letsencrypt.client import interfaces

# this should be provided by the user!

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
        keypair valid for the provided zone.

   :returns: Add record DNS message.
   :rtype: dns.message.Message

    """
    challenge_subdomain = "_acme-challenge.%s" % (zone)

    challenge_request = dns.update.Update(zone, keyring=keyring)
    # check challenge_subdomain is absent
    challenge_request.absent(challenge_subdomain)
    # add challenge_subdomain TXT with token
    challenge_request.add(
        challenge_subdomain, constants.DNS_CHALLENGE_TTL, "TXT", token)

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
    challenge_subdomain = "_acme-challenge.%s" % (zone)

    challenge_request = dns.update.Update(zone, keyring=keyring)
    # check challenge_subdomain is present
    challenge_request.present(challenge_subdomain)
    # delete challegen_subdomain TXT
    challenge_request.delete(challenge_subdomain)

    # return req
    return challenge_request

def send_request(
        gen_request, zone, token, keyring, server, port):
    """Generate and send request to DNS server.

    Generates a DNS message based on function passed as `gen_request`
   (either `add_record` or `del_record`) and then sends it to the DNS
   server specified by `server` at `port`. If the DNS request fails for
   any reason `LetsEncryptDNSAuthError` willbe raised, otherwise `True`
   will be returned.

   :param function gen_request: Function (either `add_record` or `del_record`)
        to use to generate the relevant DNS message.
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
        1: 'Malformed DNS message',
        2: 'Server failed',
        3: 'Domain does not exist on DNS server (%s)' % (zone),
        4: 'DNS server does not support that opcode',
        5: ('DNS server refuses to perform the specified '
            'operation for policy or security reasons'),
        6: 'Name exists when it should not (_acme-challenge.%s)' % (zone),
        7: ('Records that should not exist do exist (_acme-challenge.%s)'
            % (zone)),
        8: ('Records that should exist do not exist (_acme-challenge.%s)'
            % (zone)),
        9: ('Server is not authorized or is using bad TSIG key to '
            'make updates to zone "%s"' % (zone)),
        10: ('Zone "%s" does not exist' % (zone)),
        16: ('Server is using bad TSIG key to '
                    'make updates to zone "%s"' % (zone)),
        17: ('Server is using bad TSIG key to '
                    'make updates to zone "%s"' % (zone))
        }

    try:
        response = dns.query.tcp(
            dns_request,
            server, port=port,
            source_port=constants.DNS_CHALLENGE_SOURCE_PORT,
            timeout=constants.DNS_CHALLENGE_TIMEOUT
        )

        if response.rcode() == 0:
            return True
        else:
            raise errors.LetsEncryptDNSAuthError(
                rcode_errors.get("DNS Error: %s" % (response.rcode())))

    except (NoAnswer, UnexpectedSource, BadResponse,
                OSError) as err: # TimeoutError doesn't exist in 2.7 afaik
        # elif isinstance(err, TimeoutError):
        #     dns_error = "DNS Error: DNS request timed out!"
        if isinstance(err, NoAnswer):
            dns_error = "DNS Error: Did not recieve a response to DNS request!"
        elif isinstance(err, UnexpectedSource):
            dns_error = ("DNS Error: Recieved response to DNS request from "
                         "unexpected source!")
        elif isinstance(err, BadResponse):
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

    @staticmethod
    def get_chall_pref(unused_domain):
        """Get challenge preferences.

        :returns: A list containing only 'challenges.DNS'.

        """
        return [challenges.DNS]

    def perform(self, achalls):
        """Perform the challenges.

        """
        if not achalls or not isinstance(achalls, list):
            raise ValueError(".perform() was called without challenge list")
        responses = []
        for achall in achalls:
            if isinstance(achall, achallenges.DNS):
                zone = achall.domain
                # this could be cleaned up, esp since we use it here and in
                # cleanup, could prob just be a function...
                tsig = [
                    [t[0], t[1]] for t in self.dns_tsig_keys if zone in t[2]
                ]
                if not tsig:
                    raise ValueError(
                        "No TSIG key provided for domain '%s'" % (zone))
                tsig_keyring = dns.tsigkeyring.from_text(
                    {tsig[0][0]: tsig[0][1]})
                token = achall.token

                # send request
                if send_request(
                    add_record,
                    zone,
                    token,
                    tsig_keyring,
                    self.dns_server,
                    self.dns_server_port
                ):
                    responses.append(challenges.DNSResponse())
            else:
                raise errors.LetsEncryptDNSAuthError("Unexpected Challenge")
        return responses

    def cleanup(self, achalls):
        """Clean up, remove all challenge subdomains that were provisioned.

        """
        if not achalls or not isinstance(achalls, list):
            raise ValueError(".cleanup() was called without challenge list")
        for achall in achalls:
            if isinstance(achall, achallenges.DNS):
                zone = achall.domain
                tsig = [
                    [t[0], t[1]] for t in self.dns_tsig_keys if zone in t[2]
                ]
                if not tsig:
                    raise ValueError(
                        "No TSIG key provided for domain '%s'" % (zone))
                tsig_keyring = dns.tsigkeyring.from_text(
                    {tsig[0][0]: tsig[0][1]})
                token = achall.token

                # send it, raises error on absent records etc...
                send_request(
                    del_record,
                    zone,
                    token,
                    tsig_keyring,
                    self.dns_server,
                    self.dns_server_port
                )
            else:
                raise errors.LetsEncryptDNSAuthError("Unexpected Challenge")
