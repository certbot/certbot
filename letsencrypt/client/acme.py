"""ACME protocol messages."""
import json
import pkg_resources

import jsonschema

from letsencrypt.client import crypto_util
from letsencrypt.client import le_util


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
            "statusRequest",
        ]
])


def acme_object_validate(json_string, schemata=None):
    """Validate a JSON string against the ACME protocol using JSON Schema.

    :param json_string: Well-formed input JSON string.
    :type json_string: str

    :param schemata: Mapping from type name to JSON Schema definition.
                     Useful for testing.
    :type schemata: dict

    :returns: None if validation was successful.
    :raises: jsonschema.ValidationError if validation was unsuccessful
             ValueError if the object cannot even be parsed as valid JSON

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


def challenge_request(names):
    """Create ACME "challengeRequest message.

    TODO: Temporarily only enabling one name

    :param names: TODO
    :type names: list

    :returns: ACME "challengeRequest" message.
    :rtype: dict

    """
    return {
        "type": "challengeRequest",
        "identifier": names[0],
    }


def authorization_request(req_id, name, server_nonce, responses, key_file):
    """Create ACME "authoriazationRequest" message.

    :param req_id: TODO
    :type req_id: TODO

    :param name: TODO
    :type name: TODO

    :param server_nonce: TODO
    :type server_nonce: TODO

    :param responses: TODO
    :type response: TODO

    :param key_file: TODO
    :type key_file: TODO

    :returns: ACME "authoriazationRequest" message.
    :rtype: dict

    """
    return {
        "type": "authorizationRequest",
        "sessionID": req_id,
        "nonce": server_nonce,
        "responses": responses,
        "signature": crypto_util.create_sig(
            name + le_util.jose_b64decode(server_nonce), key_file),
    }


def certificate_request(csr_der, key):
    """Create ACME "certificateRequest" message.

    :param csr_der: TODO
    :type csr_der: TODO

    :param key: TODO
    :type key: TODO

    :returns: ACME "certificateRequest" message.
    :rtype: dict

    """
    return {
        "type": "certificateRequest",
        "csr": le_util.jose_b64encode(csr_der),  # TODO: csr_der.encode?
        "signature": crypto_util.create_sig(csr_der, key),
    }


def revocation_request(key_file, cert_der):
    """Create ACME "revocationRequest" message.

    :param key_file: Path to a file containing RSA key. Accepted formats
                     are the same as for `Crypto.PublicKey.RSA.importKey`.
    :type key_file: str

    :param cert_der: DER encoded certificate.
    :type cert_der: str

    :returns: ACME "revocationRequest" message.
    :rtype: dict

    """
    return {
        "type": "revocationRequest",
        "certificate": le_util.jose_b64encode(cert_der),  # TODO: csr_der.encode?
        "signature": crypto_util.create_sig(cert_der, key_file),
    }


def status_request(token):
    """Create ACME "statusRequest" message.

    :param token: Token provided in ACME "defer" message.
    :type token: str

    :returns: ACME "statusRequest" message.
    :rtype: dict

    """
    return {
        "type": "statusRequest",
        "token": token,
    }
