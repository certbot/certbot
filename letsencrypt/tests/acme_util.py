"""ACME utilities for testing."""
import datetime
import itertools

from acme import challenges
from acme import jose
from acme import messages

from letsencrypt.tests import test_util


KEY = test_util.load_rsa_private_key('rsa512_key.pem')

# Challenges
HTTP01 = challenges.HTTP01(
    token="evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA")
DVSNI = challenges.DVSNI(
    token=jose.b64decode(b"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJyPCt92wrDoA"))
DNS = challenges.DNS(token="17817c66b60ce2e4012dfad92657527a")
RECOVERY_CONTACT = challenges.RecoveryContact(
    activation_url="https://example.ca/sendrecovery/a5bd99383fb0",
    success_url="https://example.ca/confirmrecovery/bb1b9928932",
    contact="c********n@example.com")
POP = challenges.ProofOfPossession(
    alg="RS256", nonce=jose.b64decode("eET5udtV7aoX8Xl8gYiZIA"),
    hints=challenges.ProofOfPossession.Hints(
        jwk=jose.JWKRSA(key=KEY.public_key()),
        cert_fingerprints=(
            "93416768eb85e33adc4277f4c9acd63e7418fcfe",
            "16d95b7b63f1972b980b14c20291f3c0d1855d95",
            "48b46570d9fc6358108af43ad1649484def0debf"
        ),
        certs=(),  # TODO
        subject_key_identifiers=("d0083162dcc4c8a23ecb8aecbd86120e56fd24e5"),
        serial_numbers=(34234239832, 23993939911, 17),
        issuers=(
            "C=US, O=SuperT LLC, CN=SuperTrustworthy Public CA",
            "O=LessTrustworthy CA Inc, CN=LessTrustworthy But StillSecure",
        ),
        authorized_for=("www.example.com", "example.net"),
    )
)

CHALLENGES = [HTTP01, DVSNI, DNS, RECOVERY_CONTACT, POP]
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

    if status == messages.STATUS_VALID:
        kwargs.update({"validated": datetime.datetime.now()})

    return messages.ChallengeBody(**kwargs)  # pylint: disable=star-args


# Pending ChallengeBody objects
DVSNI_P = chall_to_challb(DVSNI, messages.STATUS_PENDING)
HTTP01_P = chall_to_challb(HTTP01, messages.STATUS_PENDING)
DNS_P = chall_to_challb(DNS, messages.STATUS_PENDING)
RECOVERY_CONTACT_P = chall_to_challb(RECOVERY_CONTACT, messages.STATUS_PENDING)
POP_P = chall_to_challb(POP, messages.STATUS_PENDING)

CHALLENGES_P = [HTTP01_P, DVSNI_P, DNS_P, RECOVERY_CONTACT_P, POP_P]
DV_CHALLENGES_P = [challb for challb in CHALLENGES_P
                   if isinstance(challb.chall, challenges.DVChallenge)]
CONT_CHALLENGES_P = [
    challb for challb in CHALLENGES_P
    if isinstance(challb.chall, challenges.ContinuityChallenge)
]


def gen_authzr(authz_status, domain, challs, statuses, combos=True):
    """Generate an authorization resource.

    :param authz_status: Status object
    :type authz_status: :class:`acme.messages.Status`
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
        "identifier": messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value=domain),
        "challenges": challbs,
    }
    if combos:
        authz_kwargs.update({"combinations": gen_combos(challbs)})
    if authz_status == messages.STATUS_VALID:
        authz_kwargs.update({
            "status": authz_status,
            "expires": datetime.datetime.now() + datetime.timedelta(days=31),
        })
    else:
        authz_kwargs.update({
            "status": authz_status,
        })

    # pylint: disable=star-args
    return messages.AuthorizationResource(
        uri="https://trusted.ca/new-authz-resource",
        new_cert_uri="https://trusted.ca/new-cert",
        body=messages.Authorization(**authz_kwargs)
    )
