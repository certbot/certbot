"""Validate JSON objects as ACME protocol messages."""
import json
import pkg_resources

import jsonschema


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
