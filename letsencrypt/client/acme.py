#!/usr/bin/env python

# acme.py
# validate JSON objects as ACME protocol messages

import json, jsonschema

schemata = {schema: json.load(open("letsencrypt/client/schemata/%s.json" % schema)) for schema in [
  "authorization", "authorizationRequest", "certificate", "certificateRequest",
  "challenge", "challengeRequest", "defer", "error", "revocation",
  "revocationRequest", "statusRequest"]
}

def acme_object_validate(j):
    """Validate a JSON object against the ACME protocol using JSON Schema.
    Success will return None; failure to validate will raise a
    jsonschema.ValidationError exception describing the reason that the
    object could not be validated successfully."""
    j = json.loads(j)
    if not isinstance(j, dict):
        raise jsonschema.ValidationError("this is not a dictionary object")
    if "type" not in j:
        raise jsonschema.ValidationError("missing type field")
    if j["type"] not in schemata:
        raise jsonschema.ValidationError("unknown type %s" % j["type"])
    jsonschema.validate(j, schemata[j["type"]])

def pretty(s):
    """Return a pretty-printed version of any JSON string (useful when
    printing out protocol messages for debugging purposes."""
    return json.dumps(json.loads(s), indent=4)
