"""ACME utilities for testing."""
import datetime
from unittest import mock
from typing import Any
from typing import Iterable

import josepy as jose

from acme import challenges
from acme import messages
from acme.messages import ChallengeBody
from certbot.achallenges import AnnotatedChallenge
from certbot._internal import auth_handler
from certbot.tests import util

JWK = jose.JWK.load(util.load_vector('rsa512_key.pem'))
KEY = util.load_jose_rsa_private_key_pem('rsa512_key.pem')

# Challenges
HTTP01 = challenges.HTTP01(
    token=b"evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA")
DNS01 = challenges.DNS01(token=b"17817c66b60ce2e4012dfad92657527a")
DNS01_2 = challenges.DNS01(token=b"cafecafecafecafecafecafe0feedbac")
DNS_PERSIST_01 = challenges.DNSPersist01(
    issuer_domain_names=('ca.example',),
    account_uri='https://ca.example/acct/123')

CHALLENGES = [HTTP01, DNS01]


def chall_to_challb(chall: challenges.Challenge, status: messages.Status) -> messages.ChallengeBody:
    """Return ChallengeBody from Challenge."""
    kwargs = {
        "chall": chall,
        "uri": chall.typ + "_uri",
        "status": status,
    }

    if status == messages.STATUS_VALID:
        kwargs.update({"validated": datetime.datetime.now()})

    return messages.ChallengeBody(**kwargs)


# Pending ChallengeBody objects
HTTP01_P = chall_to_challb(HTTP01, messages.STATUS_PENDING)
DNS01_P = chall_to_challb(DNS01, messages.STATUS_PENDING)
DNS01_P_2 = chall_to_challb(DNS01_2, messages.STATUS_PENDING)
DNS_PERSIST_01_P = chall_to_challb(DNS_PERSIST_01, messages.STATUS_PENDING)


def gen_achall(challb: ChallengeBody, fqdn: str,
               account_hash_prefix: str | None = None) -> AnnotatedChallenge:
    """Construct an AnnotatedChallenge for the given ChallengeBody"""
    ident = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=fqdn)
    acme_client = mock.MagicMock()
    acme_client.directory.meta.account_hash_prefix = account_hash_prefix
    return auth_handler.challb_to_achall(challb, JWK, ident, acme_client)


# AnnotatedChallenge objects
HTTP01_A = gen_achall(HTTP01_P, "example.com")
DNS01_A = gen_achall(DNS01_P, "example.org")
DNS01_A_2 = gen_achall(DNS01_P_2, "esimerkki.example.org")
DNS_PERSIST_01_A = gen_achall(DNS_PERSIST_01_P, "example.net", "https://ca.example/account-hash/")
DNS_PERSIST_01_A_WILDCARD = gen_achall(DNS_PERSIST_01_P, "*.example.net",
    "https://ca.example/account-hash/")


def gen_authzr(authz_status: messages.Status, domain: str, challs: Iterable[challenges.Challenge],
               statuses: Iterable[messages.Status]) -> messages.AuthorizationResource:
    """Generate an authorization resource.

    :param authz_status: Status object
    :type authz_status: :class:`acme.messages.Status`
    :param list challs: Challenge objects
    :param list statuses: status of each challenge object

    """
    challbs = tuple(
        chall_to_challb(chall, status)
        for chall, status in zip(challs, statuses)
    )
    authz_kwargs: dict[str, Any] = {
        "identifier": messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value=domain),
        "challenges": challbs,
    }
    if authz_status == messages.STATUS_VALID:
        authz_kwargs.update({
            "status": authz_status,
            "expires": datetime.datetime.now() + datetime.timedelta(days=31),
        })
    else:
        authz_kwargs.update({
            "status": authz_status,
        })

    return messages.AuthorizationResource(
        uri="https://trusted.ca/new-authz-resource",
        body=messages.Authorization(**authz_kwargs)
    )
