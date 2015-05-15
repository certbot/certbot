"""Proof of Possession Identifier Validation Challenge."""
import M2Crypto
import os
import zope.component

from acme import challenges
from acme import jose
from acme import other

from letsencrypt import interfaces
from letsencrypt.display import util as display_util


class ProofOfPossession(object): # pylint: disable=too-few-public-methods
    """Proof of Possession Identifier Validation Challenge.

    Based on draft-barnes-acme, section 6.5.

    :ivar installer: Installer object
    :type installer: :class:`~letsencrypt.interfaces.IInstaller`

    """
    def __init__(self, installer):
        self.installer = installer

    def perform(self, achall):
        """Perform the Proof of Possession Challenge.

        :param achall: Proof of Possession Challenge
        :type achall: :class:`letsencrypt.achallenges.ProofOfPossession`

        :returns: Response or None/False if the challenge cannot be completed
        :rtype: :class:`acme.challenges.ProofOfPossessionResponse`
            or False

        """
        if (achall.alg in [jose.HS256, jose.HS384, jose.HS512] or
                not isinstance(achall.hints.jwk, achall.alg.kty)):
            return None

        for cert, key, _ in self.installer.get_all_certs_keys():
            der_cert_key = M2Crypto.X509.load_cert(cert).get_pubkey().as_der()
            try:
                cert_key = achall.alg.kty.load(der_cert_key)
            # If JWKES.load raises other exceptions, they should be caught here
            except (IndexError, ValueError, TypeError):
                continue
            if cert_key == achall.hints.jwk:
                return self._gen_response(achall, key)

        # Is there are different prompt we should give the user?
        code, key = zope.component.getUtility(
            interfaces.IDisplay).input(
                "Path to private key for identifier: %s " % achall.domain)
        if code != display_util.CANCEL:
            return self._gen_response(achall, key)

        # If we get here, the key wasn't found
        return False

    def _gen_response(self, achall, key_path): # pylint: disable=no-self-use
        """Create the response to the Proof of Possession Challenge.

        :param achall: Proof of Possession Challenge
        :type achall: :class:`letsencrypt.achallenges.ProofOfPossession`

        :param str key_path: Path to the key corresponding to the hinted to
            public key.

        :returns: Response or False if the challenge cannot be completed
        :rtype: :class:`acme.challenges.ProofOfPossessionResponse`
            or False

        """
        if os.path.isfile(key_path):
            with open(key_path, 'rb') as key:
                try:
                    # Needs to be changed if JWKES doesn't have a key attribute
                    jwk = achall.alg.kty.load(key.read())
                    sig = other.Signature.from_msg(achall.nonce, jwk.key,
                                                   alg=achall.alg)
                except (IndexError, ValueError, TypeError, jose.errors.Error):
                    return False
            return challenges.ProofOfPossessionResponse(nonce=achall.nonce,
                                                        signature=sig)
        return False
