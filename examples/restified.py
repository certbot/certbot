import logging
import os
import pkg_resources

import M2Crypto

from letsencrypt.acme import messages2
from letsencrypt.acme import jose

from letsencrypt.client import network2


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

NEW_REG_URL = 'https://www.letsencrypt-demo.org/acme/new-reg'

key = jose.JWKRSA.load(pkg_resources.resource_string(
    'letsencrypt.acme.jose', os.path.join('testdata', 'rsa512_key.pem')))
net = network2.Network(NEW_REG_URL, key)

regr = net.register(contact=(
    'mailto:cert-admin@example.com', 'tel:+12025551212'))
logging.info('Auto-accepting TOS: %s', regr.terms_of_service)
net.update_registration(regr.update(
    body=regr.body.update(agreement=regr.terms_of_service)))
logging.debug(regr)

authzr = net.request_challenges(
    identifier=messages2.Identifier(
        typ=messages2.IdentifierFQDN, value='example1.com'),
    regr=regr)
logging.debug(authzr)

authzr, retry_after = net.poll(authzr)

csr = M2Crypto.X509.load_request_string(pkg_resources.resource_string(
    'letsencrypt.client.tests', os.path.join('testdata', 'csr.pem')))
try:
    net.request_issuance(csr, (authzr,))
except messages2.Error as error:
    print error.detail
