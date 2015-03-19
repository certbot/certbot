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
	challenge_subdomain = "_acme-challenge.%s" % (zone)

	challenge_record = dns.update.Update(zone, keyring=keyring)
	# check challenge_subdomain is absent
	challenge_request.absent(challenge_subdomain)
	# add challenge_subdomain TXT with token
	challenge_request.add(challenge_subdomain, constants.DNS_CHALLENGE_TTL, "TXT", token)

	# return req
	return challenge_request

def del_record(zone, token, keyring):
	challenge_subdomain = "_acme-challenge.%s" % (zone)

	challenge_request = dns.update(zone, keyring=keyring)
	# check challenge_subdomain is present
	challenge_request.present(challenge_subdomain)
	# delete challegen_subdomain TXT
	challenge_request.delete(challenge_subdomain)

	# return req
	return challenge_request

def send_request(gen_record, zone, token, keyring, server, port, source_port, timeout):
	dns_request = gen_record(zone, token, keyring)

	# FIXME: better keyring errors (that include that key that was used)
	rcode_errors = {
		1: 'Malformed DNS message',
		2: 'Server failed',
		3: 'Domain does not exist on DNS server (%s)' % (zone),
		4: 'DNS server does not support that opcode',
		5: ('DNS server refuses to perform the specified '
		    'operation for policy or security reasons'),
		6: 'Name exists when it should not (_acme-challenge.%s)' % (zone),
		7: 'Records that should not exist do exist (_acme-challenge.%s)' % (zone),
		8: 'Records that should exist do not exist (_acme-challenge.%s)' % (zone),
		9: ('Server is not authorized or is using bad TSIG key to '
		    'make updates to zone "%s"' % (zone)),
		10: ('Zone "%s" does not exist' % (zone)),
		16: ('Server is using bad TSIG key to '
                    'make updates to zone "%s"' % (zone)),
		17: ('Server is using bad TSIG key to '
                    'make updates to zone "%s"' % (zone))
        }

	try:
		response = dns.query.tcp(dns_request, server, port=port, source_port=source_port, timeout=timeout)

		if response.rcode() == 0:
			return True
		else:
			raise errors.LetsEncryptDNSAuthError(rcode_errors.get("DNS Error: %s" % (response.rcode())))

	except (NoAnswer, UnexpectedSource, BadResponse,
                OSError) as err: # TimeoutError doesn't exist in 2.7 I dont think...
		if isinstance(err, NoAnswer):
			dns_error = "DNS Error: Did not recieve a response to DNS request!"
		elif isinstance(err, UnexpectedSource):
			dns_error = "DNS Error: Recieved response to DNS request from unexpected source!"
		elif isinstance(err, BadResponse):
			dns_error = "DNS Error: Recieved malformed response to DNS request!"
		# elif isinstance(err, TimeoutError):
		# 	dns_error = "DNS Error: DNS request timed out!"
		elif isinstance(err, OSError):
			dns_error = "DNS Error: I forgot what an OSError means in this context..."
		raise errors.LetsEncryptDNSAuthError(dns_error)

class DNSAuthenticator(object):
	zope.interface.implements(interfaces.IAuthenticator)
	
	def __init__(self, config):
		pass

	def get_chall_pref(self, unused_domain):
		return [challenges.DNS]

	def preform(self, achalls):
		if not achalls or not isinstance(achalls, list):
			raise ValueError(".perform() was called without challenge list")
		responses = []
		for achall in achalls:
			if isinstance(achall, achallenges.DNS):
				zone = achall.domain
				tsig = [t[0], t[1] for t in self.config.dns_tsig_keys if zone in [t3]]
				if not tsig:
					raise errors.LetsEncryptDNSAuthError("No TSIG key provided for domain '%s'" % (zone))
				tsig_keyring = dns.tsigkeyring.from_text({tsig[0]: tsig[1]})
				token = achall.token

				# send request
				if send_request(add_record, zone, token, tsig_keyring, self.config.dns_server, self.config.dns_server_port, constants.DNS_CHALLENGE_SOURCE_PORT, constants.DNS_CHALLENGE_TIMEOUT):
					responses.append(challenges.DNSResponse())
			else:
				raise errors.LetsEncryptDNSAuthError("Unexpected Challenge")
		return responses

	def cleanup(self, achalls):
		if not achalls or not isinstance(achalls, list):
                        raise ValueError(".cleanup() was called without challenge list")
                for achall in achalls:
                        if isinstance(achall, achallenges.DNS):
                                zone = achall.domain
                                tsig_keyring = dns.tsigkeyring.from_text({achall.tsig_key_name: achall.tsig_key})
				token = achall.token

				# send it, raises error on absent records etc...
				send_request(del_record, zone, token, tsig_keyring, DNS_SERVER, DNS_PORT, constants.DNS_CHALLENGE_SOURCE_PORT, constants.DNS_CHALLENGE_TIMEOUT)
			else:
				raise errors.LetsEncryptDNSAuthError("Unexpected Challenge")
