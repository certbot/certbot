"""Class helps construct valid ACME messages for testing."""
import os
import pkg_resources

import Crypto.PublicKey.RSA

from letsencrypt.acme import challenges
from letsencrypt.acme import jose


KEY = Crypto.PublicKey.RSA.importKey(pkg_resources.resource_string(
    "letsencrypt.client.tests", os.path.join("testdata", "rsa256_key.pem")))

# Challenges
SIMPLE_HTTPS = challenges.SimpleHTTPS(
    token="evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA")
DVSNI = challenges.DVSNI(
    r="O*\xb4-\xad\xec\x95>\xed\xa9\r0\x94\xe8\x97\x9c&6\xbf'\xb3"
      "\xed\x9a9nX\x0f'\\m\xe7\x12", nonce="a82d5ff8ef740d12881f6d3c2277ab2e")
DNS = challenges.DNS(token="17817c66b60ce2e4012dfad92657527a")
RECOVERY_CONTACT = challenges.RecoveryContact(
    activation_url="https://example.ca/sendrecovery/a5bd99383fb0",
    success_url="https://example.ca/confirmrecovery/bb1b9928932",
    contact="c********n@example.com")
RECOVERY_TOKEN = challenges.RecoveryToken()
POP = challenges.ProofOfPossession(
    alg="RS256", nonce="xD\xf9\xb9\xdbU\xed\xaa\x17\xf1y|\x81\x88\x99 ",
    hints=challenges.ProofOfPossession.Hints(
        jwk=jose.JWKRSA(key=KEY.publickey()),
        cert_fingerprints=(
            "93416768eb85e33adc4277f4c9acd63e7418fcfe",
            "16d95b7b63f1972b980b14c20291f3c0d1855d95",
            "48b46570d9fc6358108af43ad1649484def0debf"
        ),
        certs=(), # TODO
        subject_key_identifiers=("d0083162dcc4c8a23ecb8aecbd86120e56fd24e5"),
        serial_numbers=(34234239832, 23993939911, 17),
        issuers=(
            "C=US, O=SuperT LLC, CN=SuperTrustworthy Public CA",
            "O=LessTrustworthy CA Inc, CN=LessTrustworthy But StillSecure",
        ),
        authorized_for=("www.example.com", "example.net"),
    )
)

CHALLENGES = [SIMPLE_HTTPS, DVSNI, DNS, RECOVERY_CONTACT, RECOVERY_TOKEN, POP]
DV_CHALLENGES = [chall for chall in CHALLENGES
                 if isinstance(chall, challenges.DVChallenge)]
CLIENT_CHALLENGES = [chall for chall in CHALLENGES
                     if isinstance(chall, challenges.ClientChallenge)]


def gen_combos(challs):
    """Generate natural combinations for challs."""
    dv_chall = []
    renewal_chall = []

    for i, chall in enumerate(challs):  # pylint: disable=redefined-outer-name
        if isinstance(chall, challenges.DVChallenge):
            dv_chall.append(i)
        else:
            renewal_chall.append(i)

    # Gen combos for 1 of each type, lowest index first (makes testing easier)
    return tuple((i, j) if i < j else (j, i)
                 for i in dv_chall for j in renewal_chall)
