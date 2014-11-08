#!/usr/bin/env python

# acme.py
# validate JSON objects as ACME protocol messages

import json, jsonschema

schemas = {
"authorization": """{
    "id": "https://letsencrypt.org/schema/01/authorization#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for an authorization message",
    "type": "object",
    "required": ["type"],
    "properties": {
        "type" : {
            "enum" : [ "authorization" ]
        },
        "recoveryToken" : {
            "type": "string"
        },
        "identifier" : {
            "type": "string"
        },
        "jwk": {
            "type": "object"
        }
    }
}""",

"authorizationRequest": """{
    "id": "https://letsencrypt.org/schema/01/authorizationRequest#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for an authorizationRequest message",
    "type": "object",
    "required": ["type", "sessionID", "nonce", "signature", "responses"],
    "properties": {
        "type" : {
            "enum" : [ "authorizationRequest" ]
        },
        "sessionID" : {
            "type" : "string" 
        },
        "nonce" : {
            "type": "string"
        },
        "signature" : {
            "type": "object"
        },
        "responses": {
            "type": "array",
            "minItems": 1,
            "items": {
                "anyOf": [
                     { "type": "object" },
                     { "type": "null" }
                ]
            }
        },
        "contact": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string"
                }
        }
    }
}""",

"certificate": """{
    "id": "https://letsencrypt.org/schema/01/certificate#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a certificate message",
    "type": "object",
    "required": ["type", "certificate"],
    "properties": {
        "type" : {
            "enum" : [ "certificate" ]
        },
        "certificate" : {
            "type" : "string" 
        },
        "chain" : {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string"
            }
        },
        "refresh" : {
            "type": "string"
        }
    }
}""",

"certificateRequest": """{
    "id": "https://letsencrypt.org/schema/01/certificateRequest#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a certificateRequest message",
    "type": "object",
    "required": ["type", "csr", "signature"],
    "properties": {
        "type" : {
            "enum" : [ "certificateRequest" ]
        },
        "csr" : {
            "type" : "string" 
        },
        "signature" : {
            "type": "object"
        }
    }
}""",

"challenge": """{
    "id": "https://letsencrypt.org/schema/01/challenge#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a challenge message",
    "type": "object",
    "required": ["type", "sessionID", "nonce", "challenges"],
    "properties": {
        "type" : {
            "enum" : [ "challenge" ]
        },
        "sessionID" : {
            "type" : "string" 
        },
        "nonce" : {
            "type": "string"
        },
        "challenges": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object"
            }
        },
        "combinations": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "integer" 
                }
            }
        }
    }
}""",

"challengeRequest": """{
    "id": "https://letsencrypt.org/schema/01/challengeRequest#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a challengeRequest message",
    "type": "object",
    "required": ["type", "identifier"],
    "properties": {
        "type" : {
            "enum" : [ "challengeRequest" ]
        },
        "identifier" : {
            "type": "string"
        }
    }
}""",

"defer": """{
    "id": "https://letsencrypt.org/schema/01/defer#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a defer message",
    "type": "object",
    "required": ["type", "token"],
    "properties": {
        "type" : {
            "enum" : [ "defer" ]
        },
        "token" : {
            "type": "string"
        },
        "interval" : {
            "type": "integer"
        },
        "message": {
            "type": "string"
        }
    }
}""",

"error": """{
    "id": "https://letsencrypt.org/schema/01/error#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for an error message",
    "type": "object",
    "required": ["type", "error"],
    "properties": {
        "type" : {
            "enum" : [ "error" ]
        },
        "error" : {
            "enum" : [ "malformed", "unauthorized", "serverInternal", "nonSupported", "unknown", "badCSR" ]
        },
        "message" : {
            "type": "string"
        },
        "moreInfo": {
            "type": "string"
        }
    }
}""",

"revocation": """{
    "id": "https://letsencrypt.org/schema/01/revocation#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a revocation message",
    "type": "object",
    "required": ["type"],
    "properties": {
        "type" : {
            "enum" : [ "revocation" ]
        }
    }
}""",

"revocationRequest": """{
    "id": "https://letsencrypt.org/schema/01/revocationRequest#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a revocationRequest message",
    "type": "object",
    "required": ["type", "certificate", "signature"],
    "properties": {
        "type" : {
            "enum" : [ "revocationRequest" ]
        },
        "certificate" : {
            "type" : "string" 
        },
        "signature" : {
            "type": "object"
        }
    }
}""",

"statusRequest": """{
    "id": "https://letsencrypt.org/schema/01/statusRequest#",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "Schema for a statusRequest message",
    "type": "object",
    "required": ["type", "token"],
    "properties": {
        "type" : {
            "enum" : [ "statusRequest" ]
        },
        "token" : {
            "type": "string"
        }
    }
}"""
}

schemas = {name: json.loads(schema) for name, schema in schemas.iteritems()}

def acme_object_validate(j):
    j = json.loads(j)
    if not isinstance(j, dict):
        raise jsonschema.ValidationError("this is not a dictionary object")
    if not j.has_key("type"):
        raise jsonschema.ValidationError("missing type field")
    jsonschema.validate(j, schemas[j["type"]])

