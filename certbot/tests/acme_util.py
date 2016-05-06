"""ACME utilities for testing."""
import datetime
import itertools

from acme import challenges
from acme import jose
from acme import messages

from certbot.tests import test_util


KEY = test_util.load_rsa_private_key('rsa512_key.pem')

# Challenges
HTTP01 = challenges.HTTP01(
    token="evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA")
TLSSNI01 = challenges.TLSSNI01(
    token=jose.b64decode(b"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJyPCt92wrDoA"))
DNS = challenges.DNS(token="17817c66b60ce2e4012dfad92657527a")

CHALLENGES = [HTTP01, TLSSNI01, DNS]


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
DNS_P = chall_to_challb(DNS, messages.STATUS_PENDING)

CHALLENGES_P = [HTTP01_P, TLSSNI01_P, DNS_P]


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
