"""Example script showing how to use acme client API."""
import logging
import os
import pkg_resources

import Crypto.PublicKey.RSA
import M2Crypto

from acme import client
from acme import messages
from acme import jose


logging.basicConfig(level=logging.DEBUG)


NEW_REG_URL = 'https://www.letsencrypt-demo.org/acme/new-reg'
BITS = 2048  # minimum for Boulder
DOMAIN = 'example1.com'  # example.com is ignored by Boulder

key = jose.JWKRSA.load(
    Crypto.PublicKey.RSA.generate(BITS).exportKey(format="PEM"))
acme = client.Client(NEW_REG_URL, key)

regr = acme.register(contact=())
logging.info('Auto-accepting TOS: %s', regr.terms_of_service)
acme.update_registration(regr.update(
    body=regr.body.update(agreement=regr.terms_of_service)))
logging.debug(regr)

authzr = acme.request_challenges(
    identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=DOMAIN),
    new_authzr_uri=regr.new_authzr_uri)
logging.debug(authzr)

authzr, authzr_response = acme.poll(authzr)

csr = M2Crypto.X509.load_request_string(pkg_resources.resource_string(
    'acme.jose', os.path.join('testdata', 'csr.der')),
    M2Crypto.X509.FORMAT_DER)
try:
    acme.request_issuance(csr, (authzr,))
except messages.Error as error:
    print ("This script is doomed to fail as no authorization "
           "challenges are ever solved. Error from server: {0}".format(error))
