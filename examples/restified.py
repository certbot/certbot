import httplib
import logging
import os
import pkg_resources
import requests

from letsencrypt.acme import messages2
from letsencrypt.acme import jose


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

URL_ROOT = 'https://www.letsencrypt-demo.org'
NEW_AUTHZ_URL = URL_ROOT + '/acme/new-authz'
NEW_CERT_URL = URL_ROOT + '/acme/new-certz'


class Resource(jose.ImmutableMap):
    __slots__ = ('body', 'location')


def send(resource, key, alg=jose.RS256):
    dumps = resource.body.json_dumps()
    logging.debug('Serialized JSON: %s', dumps)
    sig = jose.JWS.sign(payload=dumps, key=key, alg=alg).json_dumps()
    logging.debug('Serialized JWS: %s', sig)

    response = requests.post(resource.location, sig)
    logging.debug('Received response %s: %s', response, response.text)

    if (response.status_code == httplib.OK or
        response.status_code == httplib.CREATED):
        pass

    # TODO: server might override NEW_AUTHZ_URI (after new-reg) or
    # NEW_CERTZ_URI (after new-authz) and we should use it
    # instead. Below code only prints the link.
    if 'next' in response.links:
        logging.debug('Link (next): %s', response.links['next']['url'])
    if 'up' in response.links:
        logging.debug('Link (up): %s', response.links['up']['url'])

    # TODO: new-cert response is not JSON
    return Resource(
        body=type(resource.body).from_json(response.json()),
        location=response.headers['location'])


registration = messages2.Registration(contact=(
    'mailto:cert-admin@example.com', 'tel:+12025551212'))
key = jose.JWKRSA.load(pkg_resources.resource_string(
    'letsencrypt.acme.jose', os.path.join('testdata', 'rsa512_key.pem')))

authz = Resource(body=messages2.Authorization(identifier=messages2.Identifier(
    typ=messages2.Identifier.FQDN, value="example1.com")),
    location=NEW_AUTHZ_URL)

authz2 = send(authz, key)
assert authz2.body.key == key.public()
assert authz2.body.identifier == authz.body.identifier
assert authz2.body.challenges is not None

print authz2
print
print requests.get(authz2.location).json()
