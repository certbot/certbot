"""Validate JSON objects as ACME protocol messages."""
import json
import pkg_resources

import jsonschema


SCHEMATA = {
    schema: json.load(open(pkg_resources.resource_filename(
        __name__, "schemata/%s.json" % schema))) for schema in [
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
}


def acme_object_validate(j):
    """Validate a JSON object against the ACME protocol using JSON Schema.

    Success will return None; failure to validate will raise a
    jsonschema.ValidationError exception describing the reason that the
    object could not be validated successfully, or a ValueError exception
    if the object cannot even be parsed as valid JSON.
    """
    j = json.loads(j)
    if not isinstance(j, dict):
        raise jsonschema.ValidationError("this is not a dictionary object")
    if "type" not in j:
        raise jsonschema.ValidationError("missing type field")
    if j["type"] not in SCHEMATA:
        raise jsonschema.ValidationError("unknown type %s" % j["type"])
    jsonschema.validate(j, SCHEMATA[j["type"]])


def pretty(json_string):
    """Return a pretty-printed version of any JSON string.

    Useful when printing out protocol messages for debugging purposes.
    """
    return json.dumps(json.loads(json_string), indent=4)
