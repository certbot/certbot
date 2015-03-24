import logging
import os
import pkg_resources

from letsencrypt.acme import messages2
from letsencrypt.acme import jose

from letsencrypt.client import network2


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

URL_ROOT = 'https://www.letsencrypt-demo.org'
NEW_REG_URL = URL_ROOT + '/acme/new-reg'
NEW_AUTHZ_URL = URL_ROOT + '/acme/new-authz'
#NEW_CERT_URL = URL_ROOT + '/acme/new-certz'


key = jose.JWKRSA.load(pkg_resources.resource_string(
    'letsencrypt.acme.jose', os.path.join('testdata', 'rsa512_key.pem')))
net = network2.Network(NEW_REG_URL, key)

regr = net.register(contact=(
    'mailto:cert-admin@example.com', 'tel:+12025551212'))
logging.debug(regr)

authzr = net.request_challenges(
    identifier=messages2.Identifier(
        typ=messages2.IdentifierFQDN, value="example1.com"),
    regr=regr)

print authzr
