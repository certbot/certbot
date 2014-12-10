"""ACME protocol messages."""
import json
import pkg_resources

import jsonschema

from letsencrypt.client import crypto_util
from letsencrypt.client import le_util

# pylint: disable=no-member
SCHEMATA = dict([
    (schema, json.load(open(pkg_resources.resource_filename(
        __name__, "schemata/%s.json" % schema)))) for schema in [
            "authorization",
            "authorizationRequest",
            "certificate",
            "certificateRequest",
            "challenge",
            "challengeRequest",
            "defer",
            "error",
            "revocation",
            "revocationRequest",
            "statusRequest"
        ]
])


def acme_object_validate(json_string, schemata=None):
    """Validate a JSON string against the ACME protocol using JSON Schema.

    :param str json_string: Well-formed input JSON string.

    :param dict schemata: Mapping from type name to JSON Schema
        definition. Useful for testing.

    :returns: None if validation was successful.

    :raises jsonschema.ValidationError: if validation was unsuccessful
    :raises ValueError: if the object cannot even be parsed as valid JSON

    """
    schemata = SCHEMATA if schemata is None else schemata
    json_object = json.loads(json_string)
    if not isinstance(json_object, dict):
        raise jsonschema.ValidationError("this is not a dictionary object")
    if "type" not in json_object:
        raise jsonschema.ValidationError("missing type field")
    if json_object["type"] not in schemata:
        raise jsonschema.ValidationError(
            "unknown type %s" % json_object["type"])
    jsonschema.validate(json_object, schemata[json_object["type"]])


def pretty(json_string):
    """Return a pretty-printed version of any JSON string.

    Useful when printing out protocol messages for debugging purposes.

    """
    return json.dumps(json.loads(json_string), indent=4)


def challenge_request(name):
    """Create ACME "challengeRequest message.

    :param str name: Domain name

    :returns: ACME "challengeRequest" message.
    :rtype: dict

    """
    return {
        "type": "challengeRequest",
        "identifier": name,
    }


def authorization_request(req_id, name, server_nonce, responses, key,
                          nonce=None):
    """Create ACME "authorizationRequest" message.

    :param str req_id: SessionID from the server challenge
    :param str name: Hostname
    :param str server_nonce: Nonce from the server challenge
    :param list responses: List of completed challenges
    :param str key: Key in string form. Accepted formats
        are the same as for `Crypto.PublicKey.RSA.importKey`.
    :param str nonce: Nonce used for signature. Useful for testing.

    :returns: ACME "authorizationRequest" message.
    :rtype: dict

    """
    return {
        "type": "authorizationRequest",
        "sessionID": req_id,
        "nonce": server_nonce,
        "responses": responses,
        "signature": crypto_util.create_sig(
            name + le_util.jose_b64decode(server_nonce), key, nonce),
    }


def certificate_request(csr_der, key, nonce=None):
    """Create ACME "certificateRequest" message.

    :param str csr_der: DER encoded CSR.
    :param str key: Key in string form. Accepted formats
        are the same as for `Crypto.PublicKey.RSA.importKey`.
    :param str nonce: Nonce used for signature. Useful for testing.

    :returns: ACME "certificateRequest" message.
    :rtype: dict

    """
    return {
        "type": "certificateRequest",
        "csr": le_util.jose_b64encode(csr_der),
        "signature": crypto_util.create_sig(csr_der, key, nonce),
    }


def revocation_request(cert_der, key, nonce=None):
    """Create ACME "revocationRequest" message.

    :param str cert_der: DER encoded certificate.
    :param str key: Key in string form. Accepted formats
        are the same as for `Crypto.PublicKey.RSA.importKey`.
    :param str nonce: Nonce used for signature. Useful for testing.

    :returns: ACME "revocationRequest" message.
    :rtype: dict

    """
    return {
        "type": "revocationRequest",
        "certificate": le_util.jose_b64encode(cert_der),
        "signature": crypto_util.create_sig(cert_der, key, nonce),
    }


def status_request(token):
    """Create ACME "statusRequest" message.

    :param unicode token: Token provided in ACME "defer" message.

    :returns: ACME "statusRequest" message.
    :rtype: dict

    """
    return {
        "type": "statusRequest",
        "token": token,
    }
