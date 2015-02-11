"""Challenge specific utility functions."""
import collections
import hashlib

from Crypto import Random

from letsencrypt.client import constants
from letsencrypt.client import crypto_util
from letsencrypt.client import le_util


# Authenticator Challenges
DvsniChall = collections.namedtuple("DvsniChall", "domain, r_b64, nonce, key")
SimpleHttpsChall = collections.namedtuple(
    "SimpleHttpsChall", "domain, token, key")
DnsChall = collections.namedtuple("DnsChall", "domain, token")

# Client Challenges
RecContactChall = collections.namedtuple(
    "RecContactChall", "domain, a_url, s_url, contact")
RecTokenChall = collections.namedtuple("RecTokenChall", "domain")
PopChall = collections.namedtuple("PopChall", "domain, alg, nonce, hints")

# Helper Challenge Wrapper - Can be used to maintain the proper position of
# the response within a larger challenge list
IndexedChall = collections.namedtuple("IndexedChall", "chall, index")


# DVSNI Challenge functions
def dvsni_gen_cert(name, r_b64, nonce, key):
    """Generate a DVSNI cert and save it to filepath.

    :param str name: domain to validate
    :param str r_b64: jose base64 encoded dvsni r value
    :param str nonce: hex value of nonce

    :param key: Key to perform challenge
    :type key: :class:`letsencrypt.client.le_util.Key`

    :returns: tuple of (cert_pem, s) where
        cert_pem is the certificate in pem form
        s is the dvsni s value, jose base64 encoded
    :rtype: tuple

    """
    # Generate S
    dvsni_s = Random.get_random_bytes(constants.S_SIZE)
    dvsni_r = le_util.jose_b64decode(r_b64)

    # Generate extension
    ext = _dvsni_gen_ext(dvsni_r, dvsni_s)

    cert_pem = crypto_util.make_ss_cert(
        key.pem, [nonce + constants.DVSNI_DOMAIN_SUFFIX, name, ext])

    return cert_pem, le_util.jose_b64encode(dvsni_s)


def _dvsni_gen_ext(dvsni_r, dvsni_s):
    """Generates z extension to be placed in certificate extension.

    :param bytearray dvsni_r: DVSNI r value
    :param bytearray dvsni_s: DVSNI s value

    :returns: z + :const:`~letsencrypt.client.constants.DVSNI_DOMAIN_SUFFIX`
    :rtype: str

    """
    z_base = hashlib.new("sha256")
    z_base.update(dvsni_r)
    z_base.update(dvsni_s)

    return z_base.hexdigest() + constants.DVSNI_DOMAIN_SUFFIX
