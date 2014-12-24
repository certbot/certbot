"""Challenge specific utility functions."""
import hashlib

from Crypto import Random

from letsencrypt.client import CONFIG
from letsencrypt.client import crypto_util
from letsencrypt.client import le_util


# DVSNI Challenge functions
def dvsni_gen_cert(filepath, name, r_b64, nonce, key):
    """Generate a DVSNI cert and save it to filepath.

    :param str filepath: destination to save certificate. This will overwrite
        any file that is currently at the location.
    :param str name: domain to validate
    :param str r_b64: jose base64 encoded dvsni r value
    :param str nonce: hex value of nonce

    :param key: Key to perform challenge
    :type key: :class:`letsencrypt.client.client.Client.Key`

    :returns: dvsni s value jose base64 encoded
    :rtype: str

    """
    # Generate S
    dvsni_s = Random.get_random_bytes(CONFIG.S_SIZE)
    dvsni_r = le_util.jose_b64decode(r_b64)

    # Generate extension
    ext = _dvsni_gen_ext(dvsni_r, dvsni_s)

    cert_pem = crypto_util.make_ss_cert(
        key.pem, [nonce + CONFIG.INVALID_EXT, name, ext])

    with open(filepath, 'w') as chall_cert_file:
        chall_cert_file.write(cert_pem)

    return le_util.jose_b64encode(dvsni_s)


def _dvsni_gen_ext(dvsni_r, dvsni_s):
    """Generates z extension to be placed in certificate extension.

    :param bytearray dvsni_r: DVSNI r value
    :param bytearray dvsni_s: DVSNI s value

    :returns: z + CONFIG.INVALID_EXT
    :rtype: str

    """
    z_base = hashlib.new('sha256')
    z_base.update(dvsni_r)
    z_base.update(dvsni_s)

    return z_base.hexdigest() + CONFIG.INVALID_EXT
