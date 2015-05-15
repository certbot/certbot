"""Let's Encrypt DNS Authenticator"""
import logging

import dns.exception
import dns.query
import dns.rcode
import dns.resolver
import dns.tsigkeyring
import dns.update

import zope.interface

from acme import challenges
from letsencrypt import interfaces
from letsencrypt.plugins import common as core_plugins_common

from letsencrypt_dns import constants
from letsencrypt_dns import errors
from letsencrypt_dns import util


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
    challenge_request.absent(challenges.DNS.LABEL)
    # add challenge_subdomain TXT with token
    challenge_request.add(
        challenges.DNS.LABEL, constants.TTL, "TXT", token)

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
    challenge_request.present(challenges.DNS.LABEL)
    # delete challegen_subdomain TXT
    challenge_request.delete(challenges.DNS.LABEL)

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
                             % (challenges.DNS.LABEL, zone)),
        dns.rcode.YXRRSET: ('Records that should not exist do exist (%s.%s)'
                            % (challenges.DNS.LABEL, zone)),
        dns.rcode.NXRRSET: ('Records that should exist do not exist (%s.%s)'
                            % (challenges.DNS.LABEL, zone)),
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
                             source_port=constants.SOURCE_PORT,
                             timeout=constants.TIMEOUT)
    except dns.resolver.NoAnswer as error:
        logging.exception(error)
        raise errors.Error("Did not recieve a response to DNS request!")
    except dns.query.UnexpectedSource as error:
        logging.exception(error)
        raise errors.Error(
            "Recieved response to DNS request from unexpected source!")
    except dns.query.BadResponse as error:
        logging.exception(error)
        raise errors.Error("Recieved malformed response to DNS request!")
    except OSError as error:
        logging.exception(error)
        # TODO(rolandshoemaker)
        raise errors.Error("I forgot what an OSError means in this context...")
    except dns.exception.Timeout as error:
        logging.exception(error)
        raise errors.Error("DNS request timed out!")

    if resp.rcode() == 0:
        return True
    else:
        raise errors.Error("DNS Error: %s" % (rcode_errors.get(resp.rcode())))


class DNSAuthenticator(core_plugins_common.Plugin):
    """DNS Authenticator

    This authenticator interacts with an already configured DNS
    server in order to provision subdomains in response to DNS
    challenges from the certificate authority.

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    @classmethod
    def add_parser_arguments(cls, add):
        add("server", default=constants.CLI_DEFAULTS["server"],
            help="DNS server hostname used to create challenge subdomains.")
        add("server-port", default=constants.CLI_DEFAULTS["server_port"],
            help="DNS server port to use.")
        add("tsig-keys", nargs="+", type=util.split_tsig_keys, help="DNS "
            "TSIG keys for updates in the format: keyname,keysecret,domains+")

    def __init__(self, *args, **kwargs):
        super(DNSAuthenticator, self).__init__(*args, **kwargs)
        if self.conf("tsig_keys") is None:
            raise errors.Error("No TSIG keys provided.")

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
            tsig_keyring = find_valid_key(self.conf("tsig_keys"), zone)
            if not tsig_keyring:
                raise errors.Error("No TSIG keypair provided for %s" % (zone))

            # send request
            if send_request(add_record, zone, token, tsig_keyring,
                            self.conf("server"), self.conf("server_port")):
                responses.append(challenges.DNSResponse())
        return responses

    def cleanup(self, achalls):
        """Clean up, remove all challenge subdomains that were provisioned."""
        for achall in achalls:
            zone = achall.domain
            token = achall.token
            tsig_keyring = find_valid_key(self.conf("tsig_keys"), zone)
            if not tsig_keyring:
                raise errors.Error("No TSIG keypair provided for %s" % (zone))

            # send it, raises error on absent records etc...
            send_request(del_record, zone, token, tsig_keyring,
                         self.conf("server"), self.conf("server_port"))
