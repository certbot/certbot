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
    j = json.loads(j)
    if not isinstance(j, dict):
        raise jsonschema.ValidationError("this is not a dictionary object")
    if not j.has_key("type"):
        raise jsonschema.ValidationError("missing type field")
    if not schemata.has_key(j["type"]):
        raise jsonschema.ValidationError("unknown type %s" % j["type"])
    jsonschema.validate(j, schemata[j["type"]])

