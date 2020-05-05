"""
Given an ACME account key as input, deactivate the account.

This can be useful if you created an account with a non-Certbot client and now
want to deactivate it.

Private key should be in PKCS#8 PEM form.

To provide the URL for the ACME server you want to use, set it in the $DIRECTORY
environment variable, e.g.:

DIRECTORY=https://acme-staging.api.letsencrypt.org/directory python \
    deactivate.py private_key.pem
"""
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import josepy as jose

from acme import client as acme_client
from acme import errors as acme_errors
from acme import messages

DIRECTORY = os.getenv('DIRECTORY', 'http://localhost:4000/directory')

if len(sys.argv) != 2:
    print("Usage: python deactivate.py private_key.pem")
    sys.exit(1)

data = open(sys.argv[1], "r").read()
key = jose.JWKRSA(key=serialization.load_pem_private_key(
    data, None, default_backend()))

net = acme_client.ClientNetwork(key, verify_ssl=False,
                                user_agent="acme account deactivator")

client = acme_client.Client(DIRECTORY, key=key, net=net)
try:
    # We expect this to fail and give us a Conflict response with a Location
    # header pointing at the account's URL.
    client.register()
except acme_errors.ConflictError as e:
    location = e.location
if location is None:
    raise "Key was not previously registered (but now is)."
client.deactivate_registration(messages.RegistrationResource(uri=location))
