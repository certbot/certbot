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

contact = contact=('mailto:cert-admin@example.com', 'tel:+12025551212')
# Boulder does not support registrations
#regr = net.register(contact=contact)
regr = messages2.RegistrationResource(
    body=messages2.Registration(contact=contact, key=key.public()),
    uri=NEW_REG_URL + '/fooooo',
    new_authz_uri=NEW_AUTHZ_URL)

authzr = net.request_challenges(
    identifier=messages2.Identifier(
        typ=messages2.IdentifierFQDN, value="example1.com"),
    regr=regr)

print authzr
