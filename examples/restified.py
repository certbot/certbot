import logging
import os
import pkg_resources

import M2Crypto

from acme import messages2
from acme import jose

from letsencrypt import network


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

NEW_REG_URL = 'https://www.letsencrypt-demo.org/acme/new-reg'

key = jose.JWKRSA.load(pkg_resources.resource_string(
    'acme.jose', os.path.join('testdata', 'rsa512_key.pem')))
net = network.Network(NEW_REG_URL, key)

regr = net.register(contact=(
    'mailto:cert-admin@example.com', 'tel:+12025551212'))
logging.info('Auto-accepting TOS: %s', regr.terms_of_service)
net.update_registration(regr.update(
    body=regr.body.update(agreement=regr.terms_of_service)))
logging.debug(regr)

authzr = net.request_challenges(
    identifier=messages2.Identifier(
        typ=messages2.IDENTIFIER_FQDN, value='example1.com'),
    new_authzr_uri=regr.new_authzr_uri)
logging.debug(authzr)

authzr, authzr_response = net.poll(authzr)

csr = M2Crypto.X509.load_request_string(pkg_resources.resource_string(
    'letsencrypt.tests', os.path.join('testdata', 'csr.pem')))
try:
    net.request_issuance(csr, (authzr,))
except messages2.Error as error:
    print error.detail
