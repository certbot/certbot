"""Proof of Possession Identifier Validation Challenge."""
import M2Crypto
import os
import zope.component

from letsencrypt.acme import challenges
from letsencrypt.acme import jose
from letsencrypt.acme import other
from letsencrypt.client import interfaces
from letsencrypt.client.display import util as display_util


class ProofOfPossession(object): # pylint: disable=too-few-public-methods
    """Proof of Possession Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.5.

    :ivar installer: Installer object
    :type installer: :class:`~letsencrypt.client.interfaces.IInstaller`

    """
    def __init__(self, installer):
        self.installer = installer

    def perform(self, achall):
        """Perform the Proof of Possession Challenge.

        :param achall: Proof of Possession Challenge
        :type achall: :class:`letsencrypt.client.achallenges.ProofOfPossession`

        :returns: Response or None/False if the challenge cannot be completed
        :rtype: :class:`letsencrypt.acme.challenges.ProofOfPossessionResponse`
            or False

        """
        if (not isinstance(achall.challb.hints.jwk, achall.challb.alg.kty) or
                achall.challb.alg in [jose.HS256, jose.HS384, jose.HS512]):
            return None

        # This will work regardless of how JWKES is implemented
        for cert, key, _ in self.installer.get_all_certs_keys():
            der_cert_key = M2Crypto.X509.load_cert(cert).get_pubkey().as_der()
            cert_key = achall.challb.alg.kty.load(der_cert_key)
            if cert_key == achall.challb.hints.jwk:
                return self._gen_response(achall, key)

        # Is there are different prompt we should give the user?
        code, key = zope.component.getUtility(
            interfaces.IDisplay).input(
                "Path to private key for identifier: %s " % achall.domain)
        if code != display_util.CANCEL:
            return self._gen_response(achall, key)

        # If we get here, the key wasn't found
        return False

    def _gen_response(self, challb, key_path): # pylint: disable=no-self-use
        """Create the response to the Proof of Possession Challenge.

        :param challb: Proof of Possession Challenge
        :type challb: :class:`letsencrypt.acme.challenges.ProofOfPossession`

        :param str key_path: Path to the key corresponding to the hinted to
            public key.

        :returns: Response or None/False if the challenge cannot be completed
        :rtype: :class:`letsencrypt.acme.challenges.ProofOfPossessionResponse`
            or False

        """

        if os.path.isfile(key_path):
            with open(key_path, 'rb') as key:
                try:
                    jwk = challb.alg.kty.load(key.read())
                except (IndexError, ValueError, TypeError):
                    return False
            # If JWKES doesn't have a key attribute, this needs to be modified
            sig = other.Signature.from_msg(challb.nonce, jwk.key,
                                           alg=challb.alg)
            return challenges.ProofOfPossessionResponse(nonce=challb.nonce,
                                                        signature=sig)
