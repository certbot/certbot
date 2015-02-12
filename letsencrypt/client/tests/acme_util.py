"""Class helps construct valid ACME messages for testing."""
from letsencrypt.client import constants


CHALLENGES = {
    "simpleHttps":
    {
        "type": "simpleHttps",
        "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+oA"
    },
    "dvsni":
    {
        "type": "dvsni",
        "r": "Tyq0La3slT7tqQ0wlOiXnCY2vyez7Zo5blgPJ1xt5xI",
        "nonce": "a82d5ff8ef740d12881f6d3c2277ab2e"
    },
    "dns":
    {
        "type": "dns",
        "token": "17817c66b60ce2e4012dfad92657527a"
    },
    "recoveryContact":
    {
        "type": "recoveryContact",
        "activationURL": "https://example.ca/sendrecovery/a5bd99383fb0",
        "successURL": "https://example.ca/confirmrecovery/bb1b9928932",
        "contact": "c********n@example.com"
    },
    "recoveryTokent":
    {
        "type": "recoveryToken"
    },
    "proofOfPossession":
    {
        "type": "proofOfPossession",
        "alg": "RS256",
        "nonce": "eET5udtV7aoX8Xl8gYiZIA",
        "hints": {
            "jwk": {
                "kty": "RSA",
                "e": "AQAB",
                "n": "KxITJ0rNlfDMAtfDr8eAw...fSSoehDFNZKQKzTZPtQ"
            },
            "certFingerprints": [
                "93416768eb85e33adc4277f4c9acd63e7418fcfe",
                "16d95b7b63f1972b980b14c20291f3c0d1855d95",
                "48b46570d9fc6358108af43ad1649484def0debf"
            ],
            "subjectKeyIdentifiers":
            ["d0083162dcc4c8a23ecb8aecbd86120e56fd24e5"],
            "serialNumbers": [34234239832, 23993939911, 17],
            "issuers": [
                "C=US, O=SuperT LLC, CN=SuperTrustworthy Public CA",
                "O=LessTrustworthy CA Inc, CN=LessTrustworthy But StillSecure"
            ],
            "authorizedFor": ["www.example.com", "example.net"]
        }
    }
}


def get_dv_challenges():
    """Returns all auth challenges."""
    return [chall for typ, chall in CHALLENGES.iteritems()
            if typ in constants.DV_CHALLENGES]


def get_client_challenges():
    """Returns all client challenges."""
    return [chall for typ, chall in CHALLENGES.iteritems()
            if typ in constants.CLIENT_CHALLENGES]


def get_challenges():
    """Returns all challenges."""
    return [chall for chall in CHALLENGES.itervalues()]


def gen_combos(challs):
    """Generate natural combinations for challs."""
    dv_chall = []
    renewal_chall = []

    for i, chall in enumerate(challs):
        if chall["type"] in constants.DV_CHALLENGES:
            dv_chall.append(i)
        else:
            renewal_chall.append(i)

    # Gen combos for 1 of each type
    return [[i, j] for i in xrange(len(dv_chall))
            for j in xrange(len(renewal_chall))]

def get_chall_msg(iden, nonce, challenges, combos=None):
    """Produce an ACME challenge message."""
    chall_msg = {
        "type": "challenge",
        "sessionID": iden,
        "nonce": nonce,
        "challenges": challenges
    }

    if combos is None:
        return chall_msg

    chall_msg["combinations"] = combos
    return chall_msg
