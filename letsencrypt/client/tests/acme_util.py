"""Class helps construct valid ACME messages for testing."""
import datetime
import itertools
import os
import pkg_resources

import Crypto.PublicKey.RSA

from letsencrypt.acme import challenges
from letsencrypt.acme import jose
from letsencrypt.acme import messages2


KEY = jose.HashableRSAKey(Crypto.PublicKey.RSA.importKey(
    pkg_resources.resource_string(
        "letsencrypt.client.tests",
        os.path.join("testdata", "rsa256_key.pem"))))

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
CONT_CHALLENGES = [chall for chall in CHALLENGES
                   if isinstance(chall, challenges.ContinuityChallenge)]


def gen_combos(challbs):
    """Generate natural combinations for challbs."""
    dv_chall = []
    cont_chall = []

    for i, challb in enumerate(challbs):  # pylint: disable=redefined-outer-name
        if isinstance(challb.chall, challenges.DVChallenge):
            dv_chall.append(i)
        else:
            cont_chall.append(i)

    # Gen combos for 1 of each type, lowest index first (makes testing easier)
    return tuple((i, j) if i < j else (j, i)
                 for i in dv_chall for j in cont_chall)


def chall_to_challb(chall, status):  # pylint: disable=redefined-outer-name
    """Return ChallengeBody from Challenge."""
    kwargs = {
        "chall": chall,
        "uri": chall.typ + "_uri",
        "status": status,
    }

    if status == messages2.STATUS_VALID:
        kwargs.update({"validated": datetime.datetime.now()})

    return messages2.ChallengeBody(**kwargs)  # pylint: disable=star-args


# Pending ChallengeBody objects
DVSNI_P = chall_to_challb(DVSNI, messages2.STATUS_PENDING)
SIMPLE_HTTPS_P = chall_to_challb(SIMPLE_HTTPS, messages2.STATUS_PENDING)
DNS_P = chall_to_challb(DNS, messages2.STATUS_PENDING)
RECOVERY_CONTACT_P = chall_to_challb(RECOVERY_CONTACT, messages2.STATUS_PENDING)
RECOVERY_TOKEN_P = chall_to_challb(RECOVERY_TOKEN, messages2.STATUS_PENDING)
POP_P = chall_to_challb(POP, messages2.STATUS_PENDING)

CHALLENGES_P = [SIMPLE_HTTPS_P, DVSNI_P, DNS_P,
                RECOVERY_CONTACT_P, RECOVERY_TOKEN_P, POP_P]
DV_CHALLENGES_P = [challb for challb in CHALLENGES_P
                   if isinstance(challb.chall, challenges.DVChallenge)]
CONT_CHALLENGES_P = [
    challb for challb in CHALLENGES_P
    if isinstance(challb.chall, challenges.ContinuityChallenge)
]


def gen_authzr(authz_status, domain, challs, statuses, combos=True):
    """Generate an authorization resource.

    :param authz_status: Status object
    :type authz_status: :class:`letsencrypt.acme.messages2.Status`
    :param list challs: Challenge objects
    :param list statuses: status of each challenge object
    :param bool combos: Whether or not to add combinations

    """
    # pylint: disable=redefined-outer-name
    challbs = tuple(
        chall_to_challb(chall, status)
        for chall, status in itertools.izip(challs, statuses)
    )
    authz_kwargs = {
        "identifier": messages2.Identifier(
            typ=messages2.IDENTIFIER_FQDN, value=domain),
        "challenges": challbs,
    }
    if combos:
        authz_kwargs.update({"combinations": gen_combos(challbs)})
    if authz_status == messages2.STATUS_VALID:
        now = datetime.datetime.now()
        authz_kwargs.update({
            "status": authz_status,
            "expires": datetime.datetime(now.year, now.month + 1, now.day),
        })
    else:
        authz_kwargs.update({
            "status": authz_status,
        })

    # pylint: disable=star-args
    return messages2.AuthorizationResource(
        uri="https://trusted.ca/new-authz-resource",
        new_cert_uri="https://trusted.ca/new-cert",
        body=messages2.Authorization(**authz_kwargs)
    )
