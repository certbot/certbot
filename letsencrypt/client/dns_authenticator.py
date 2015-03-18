"""DNS Authenticator"""
import zope.interface
import dnspython

from letsencrypt.client import CONFIG
from letsencrypt.acme import challenges
from letsencrypt.client import errors
from letsencrypt.client import interfaces

# these should be constants prob? (dns server/port should be settable obv tho)
DNS_DEFAULT_TTL = 60
DNS_SERVER = "localhost"
DNS_PORT = 53
DNS_SOURCE_PORT = 0
DNS_TIMEOUT = 30

def add_record(zone, token, keyring):
	challenge_subdomain = "_acme-challenge.%s" % (zone)

	challenge_record = dns.update.Update(zone, keyring=keyring)
	# check absent challenge_subdomain
	challenge_request.absent(challenge_subdomain)
	# add challenge_subdomain TXT with token
	challenge_request.add(challenge_subdomain, DEFAULT_TTL, "TXT", token)

	# return req
	return challenge_request

def del_record(zone, token, keyring): # token needed?
	challenge_subdomain = "_acme-challenge.%s" % (zone)

	challenge_request = dns.update(zone, keyring=keyring)
	# check present challenge_subdomain
	challenge_request.present(challenge_subdomain)
	# delete challegen_subdomain TXT (with token?)
	challenge_request.delete(challenge_subdomain)

	# return req
	return challenge_request

def send_request(gen_record, zone, token, keyring, server, port, source_port, timeout):
	dns_request = gen_record(zone, token, keyring)

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
			return True # ???
		else:
			raise errors.LetsEncryptDNSAuthError(rcode_errors.get(response.rcode()))

	except (NoAnswer, UnexpectedSource, BadResponse,
                TimeoutError, OSError) as err:
		# FIXME: should use better error than ValueError...
		if isinstance(err, NoAnswer):
			raise ValueError("DNS Error: Did not recieve a response to DNS request!")
		elif isinstance(err, UnexpectedSource):
			raise ValueError("DNS Error: Recieved response to DNS request from unexpected source!")
		elif isinstance(err, BadResponse):
			raise ValueError("DNS Error: Recieved malformed response to DNS request!")
		elif isinstance(err, TimeoutError):
			raise ValueError("DNS Error: DNS request timed out!")
		elif isinstance(err, OSError):
			raise ValueError("DNS Error: I forgot what an OSError means in this context...")

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
				tsig_keyring = dns.tsigkeyring.from_text({achall.tsig_key_name: achall.tsig_key})
				token = achall.token

				# send request
				resp = send_request(add_record, zone, token, tsig_keyring, DNS_SERVER, DNS_PORT, DNS_SOURCE_PORT, DNS_TIMEOUT)
				# do something
				responses.append() # ???
			else:
				# uh, nothing?
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

				# send it
				send_request(del_record, zone, token, tsig_keyring, DNS_SERVER, DNS_PORT, DNS_SOURCE_PORT, DNS_TIMEOUT)
			else:
				raise errors.LetsEncryptDNSAuthError("Unexpected Challenge") 
