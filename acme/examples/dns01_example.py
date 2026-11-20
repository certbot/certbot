"""Example ACME-V2 API for DNS-01 challenge.

Brief:

This a complete usage example of the python-acme API.

Limitations of this example:
    - Works for only one Domain name
      (see acme.crypto_util.make_csr() `domains` arg to add multiple domains)
    - Performs only DNS-01 challenge
    - Uses ACME-v2

Workflow:
    (Account creation)
    - Create account key
    - Register account and accept TOS
    (Certificate actions)
    - Select DNS-01 within offered challenges by the CA server
    - Create domain private key and CSR
    - Wait for challenge TXT record to be added
    - Issue certificate
    - Renew certificate
    - Revoke certificate
    (Account update actions)
    - Change contact information
    - Deactivate Account
"""
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose

from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages

# Constants:

# This is the staging point for ACME-V2 within Let's Encrypt.
DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

USER_AGENT = 'python-acme-example'

# Account key size
ACC_KEY_BITS = 2048

# Certificate private key size
CERT_PKEY_BITS = 2048

# Domain name for the certificate.
DOMAIN = 'client.example.com'


# Useful methods and classes:


def new_csr_comp(domain_name, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        pkey = rsa.generate_private_key(public_exponent=65537, key_size=CERT_PKEY_BITS)
        pkey_pem = pkey.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.PKCS8,
                                      encryption_algorithm=serialization.NoEncryption())

    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    return pkey_pem, csr_pem


def select_dns01_chall(orderr):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.DNS01):
                return i

    raise Exception('DNS-01 challenge was not offered by the CA server.')


def perform_dns01(domain, client_acme, challb, orderr):
    """Set up standalone webserver and perform DNS-01 challenge."""

    response, validation = challb.response_and_validation(client_acme.net.key)

    input(f"Add DNS TXT record and press Enter when ready:\n"
          f"TXT Record Name: _acme-challenge.{domain}\n"
          f"Value: {validation}\n")

    # Replace it with retries
    print("Waiting 20 seconds for DNS propagation...")
    time.sleep(20)

    # Let the CA server know that we are ready for the challenge.
    client_acme.answer_challenge(challb, response)

    # Wait for challenge status and then issue a certificate.
    # It is possible to set a deadline time.
    finalized_orderr = client_acme.poll_and_finalize(orderr)

    print("Success!")

    return finalized_orderr.fullchain_pem


# Main examples:


def example_dns():
    """This example executes the whole process of fulfilling a DNS-01
    challenge for one specific domain.

    The workflow consists of:
    (Account creation)
    - Create account key
    - Register account and accept TOS
    (Certificate actions)
    - Select DNS-01 within offered challenges by the CA server
    - Create domain private key and CSR
    - Wait for challenge TXT record to be added
    - Issue certificate
    - Renew certificate
    - Revoke certificate
    (Account update actions)
    - Change contact information
    - Deactivate Account

    """
    # Create account key

    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537,
                                     key_size=ACC_KEY_BITS,
                                     backend=default_backend()))

    # Register account and accept TOS

    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(DIRECTORY_URL, net)
    client_acme = client.ClientV2(directory, net=net)

    # Terms of Service URL is in client_acme.directory.meta.terms_of_service
    # Registration Resource: regr
    regr = client_acme.new_account(
        messages.NewRegistration.from_data(terms_of_service_agreed=True))

    # Create domain private key and CSR
    pkey_pem, csr_pem = new_csr_comp(DOMAIN)

    # Issue certificate

    orderr = client_acme.new_order(csr_pem)

    # Select DNS-01 within offered challenges by the CA server
    challb = select_dns01_chall(orderr)

    # The certificate is ready to be used in the variable "fullchain_pem".
    fullchain_pem = perform_dns01(DOMAIN, client_acme, challb, orderr)

    # Renew certificate

    _, csr_pem = new_csr_comp(DOMAIN, pkey_pem)

    orderr = client_acme.new_order(csr_pem)

    challb = select_dns01_chall(orderr)

    # Performing challenge
    fullchain_pem = perform_dns01(DOMAIN, client_acme, challb, orderr)

    # Revoke certificate

    fullchain_com = x509.load_pem_x509_certificate(fullchain_pem.encode())

    try:
        client_acme.revoke(fullchain_com, 0)  # revocation reason = 0
    except errors.ConflictError:
        # Certificate already revoked.
        pass

    # Query registration status.
    client_acme.net.account = regr
    try:
        regr = client_acme.query_registration(regr)
    except errors.Error as err:
        if err.typ == messages.ERROR_PREFIX + 'unauthorized':
            # Status is deactivated.
            pass
        raise

    # Change contact information

    email = 'newfake@example.com'
    regr = client_acme.update_registration(
        regr.update(
            body=regr.body.update(
                contact=('mailto:' + email,)
            )
        )
    )

    # Deactivate account/registration

    regr = client_acme.deactivate_registration(regr)


if __name__ == "__main__":
    example_dns()
