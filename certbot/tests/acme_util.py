"""ACME utilities for testing."""
import datetime

import josepy as jose
import six

from acme import challenges
from acme import messages

from certbot import auth_handler

from certbot.tests import util


JWK = jose.JWK.load(util.load_vector('rsa512_key.pem'))
KEY = util.load_rsa_private_key('rsa512_key.pem')

# Challenges
HTTP01 = challenges.HTTP01(
    token=b"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA")
TLSSNI01 = challenges.TLSSNI01(
    token=jose.b64decode(b"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJyPCt92wrDoA"))
DNS01 = challenges.DNS01(token=b"17817c66b60ce2e4012dfad92657527a")
DNS01_2 = challenges.DNS01(token=b"cafecafecafecafecafecafe0feedbac")

CHALLENGES = [HTTP01, TLSSNI01, DNS01]


def gen_combos(challbs):
    """Generate natural combinations for challbs."""
    # completing a single DV challenge satisfies the CA
    return tuple((i,) for i, _ in enumerate(challbs))


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
TLSSNI01_P = chall_to_challb(TLSSNI01, messages.STATUS_PENDING)
HTTP01_P = chall_to_challb(HTTP01, messages.STATUS_PENDING)
DNS01_P = chall_to_challb(DNS01, messages.STATUS_PENDING)
DNS01_P_2 = chall_to_challb(DNS01_2, messages.STATUS_PENDING)

CHALLENGES_P = [HTTP01_P, TLSSNI01_P, DNS01_P]


# AnnotatedChallenge objects
HTTP01_A = auth_handler.challb_to_achall(HTTP01_P, JWK, "example.com")
TLSSNI01_A = auth_handler.challb_to_achall(TLSSNI01_P, JWK, "example.net")
DNS01_A = auth_handler.challb_to_achall(DNS01_P, JWK, "example.org")
DNS01_A_2 = auth_handler.challb_to_achall(DNS01_P_2, JWK, "esimerkki.example.org")

ACHALLENGES = [HTTP01_A, TLSSNI01_A, DNS01_A]


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
        for chall, status in six.moves.zip(challs, statuses)
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
        body=messages.Authorization(**authz_kwargs)
    )
