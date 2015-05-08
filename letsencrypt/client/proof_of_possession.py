"""Proof of Possession Identifier Validation Challenge.

Based on draft-barnes-acme, section 6.5.

"""
import M2Crypto
import os
import zope.component

from letsencrypt.acme import challenges
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.client import interfaces
from letsencrypt.client.display import util as display_util


class ProofOfPossession(object):
    """Proof of Possession Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.5.

    """
    def __init__(self, certs_keys):
        """Initializes the object with known certificates and keys.

        :param list certs_keys: tuples with form `[(cert, key, path)]`, where:
            - `cert` - str path to certificate file
            - `key` - str path to associated key file
            - `path` - file path to configuration file

        """
        self.certs_keys = certs_keys

    def perform(self, achall):
        """Perform the Proof of Possession Challenge.

        :param achall: Proof of Possession Challenge
        :type achall: :class:`letsencrypt.client.achallenges.ProofOfPossession`

        :returns: Response or None/False if the challenge cannot be completed
        :rtype: :class:`letsencrypt.acme.challenges.ProofOfPossessionResponse'
            or False

        """
        if (not isinstance(achall.challb.hints.jwk, achall.challb.alg.kty) or
                achall.challb.alg in [jose.HS256, jose.HS384, jose.HS512]):
            return None

        for cert, prv_key, _ in self.certs_keys:
            der_key = M2Crypto.X509.load_cert(cert).get_pubkey().as_der()
            cert_key = challb.alg.kty.load(der_key)
            if cert_key == challb.hints.jwk:
                return _gen_response(achall, key)

        # Is there are different prompt we should give the user?
        code, prv_key = zope.component.getUtility(
            interfaces.IDsiplay).input(
                "Path to private key for identifier: %s " % achall.domain)
        if code != display_util.CANCEL:
            return _gen_response(achall, prv_key)

        # If we get here, the key wasn't found
        return False

    def _gen_response(self, challb, key_path): # pylint: disable=no-self-use
        """Create the response to the Proof of Possession Challenge.

        :param challb: Proof of Possession Challenge
        :type challb: :class:`letsencrypt.acme.challenges.ProofOfPossession`

        :param str key_path: Path to the private key corresponding to the
            hinted to public key

        :returns: Response or None/False if the challenge cannot be completed
        :rtype: :class:`letsencrypt.acme.challenges.ProofOfPossessionResponse'
            or False

        """

        if os.path.isfile(key_path):
            with key as open(key_path, 'rb'):
                try:
                    jwk = challb.alg.kty.load(key.read())
                except (IndexError, ValueError, TypeError):
                    return False    
            sig = other.Signature.from_msg(challb.nonce, jwk, alg=challb.alg)
            return challenges.ProofOfPossessionResponse(nonce=challb.nonce,
                                                        signature=sig)
