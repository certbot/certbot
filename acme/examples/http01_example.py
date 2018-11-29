"""Example ACME-V2 API for HTTP-01 challenge.

Copyright 2018 Intra2net AG - Juliana Rodrigueiro

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Brief:

This a complete usage example of the python-acme API.

Limitations of this example:
    - Works for only one Domain name.
    - Performs only HTTP-01 challenge.
    - Uses ACME-v2

Workflow:
    - Create account key.
    - Register account and accept TOS.
    - Select HTTP-01 within offered challenges by the CA server.
    - Set up standalone web server.
    - Create domain private key and CSR.
    - Issue certificate.
    - Change contact information
    - Renew Certificate
    - Revoke Certificate
    - Deactivate Account
"""
import logging

from contextlib import contextmanager
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import OpenSSL

from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import messages
from acme import standalone
import josepy as jose

# Constants:

# This is the staging point for ACME-V2 within Let's Encrypt.
DIRECTORY_URL = 'http://boulder:4001/directory'

USER_AGENT = 'python-acme-example'

# Account key size
ACC_KEY_BITS = 2048

# Certificate private key size
CERT_PKEY_BITS = 2048

# Domain name for the certificate.
DOMAIN = 'client3.testemail5.com'

# If you are running Boulder locally, it is possible to configure any port
# number to execute the challenge, but real CA servers will obviously always
# use port 80.
PORT = 80

# ACME API can be quite verbose.
logging.basicConfig(level=logging.INFO)


# Useful methods and classes:

def generate_client_account_key():
    """Generate account key and create new client."""
    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537,
                                     key_size=ACC_KEY_BITS,
                                     backend=default_backend()))
    return create_client(acc_key)


def create_client(acc_key):
    """Create client from existing account key."""
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = messages.Directory.from_json(net.get(DIRECTORY_URL).json())
    return client.ClientV2(directory, net=net)


def new_pkey_pem():
    """Create private key."""
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, CERT_PKEY_BITS)
    pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                              pkey)
    return pkey_pem


def new_csr_comp(domain_name, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        pkey_pem = new_pkey_pem()
    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    return pkey_pem, csr_pem


def verify_registration(client_acme, regr):
    """Query registration status."""
    client_acme.net.account = regr
    try:
        return client_acme.query_registration(regr)
    except errors.Error as err:
        if err.typ == messages.OLD_ERROR_PREFIX + 'unauthorized' \
                or err.typ == messages.ERROR_PREFIX + 'unauthorized':
            logging.info('Status is deactivated')
        raise


def select_http01_chall(orderr):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.HTTP01):
                return i

    raise Exception('HTTP-01 challenge was not offered by the CA server.')


@contextmanager
def challenge_server(http_01_resources):
    """Manage standalone server set up and shutdown."""

    # Setting up a fake server that binds at PORT and any address.
    address = ('', PORT)
    try:
        servers = standalone.HTTP01DualNetworkedServers(address,
                                                        http_01_resources)
        # Start client standalone web server.
        servers.serve_forever()
        yield servers
    finally:
        # Shutdown client web server and unbind from PORT
        servers.shutdown_and_server_close()


def perform_http01(client_acme, challb, orderr):
    """Set up standalone webserver and perform HTTP-01 challenge."""

    response, validation = challb.response_and_validation(client_acme.net.key)

    resource = standalone.HTTP01RequestHandler.HTTP01Resource(
        chall=challb.chall, response=response, validation=validation)

    with challenge_server({resource}):

        # This is the domain used for the local simple_verify. This example
        # uses a fake domain name in DOMAIN, so this verification would fail
        # because the DNS would never resolve it to a real IP address. In order
        # to bypass it and only verify if the standalone server would
        # successfully reply the correct resource, we use 'localhost' as domain
        # instead.
        domain = 'localhost'
        if not response.simple_verify(challb.chall,
                                      domain,
                                      client_acme.net.key.public_key(),
                                      PORT):
            raise Exception('Verification failed')

        # Let the CA server know that we are ready for the challenge.
        client_acme.answer_challenge(challb, response)

        # Wait for challenge status and then issue a certificate.
        # It is possible to set a deadline time.
        finalized_orderr = client_acme.poll_and_finalize(orderr)

    return finalized_orderr.fullchain_pem


# Main examples:


def example_http():
    """This example executes the whole process of fulfilling a HTTP-01
    challenge for one specific domain.

    The workflow consists of:
    - Create account key.
    - Register account and accept TOS.
    - Select HTTP-01 within offered challenges by the CA server.
    - Set up http challenge resource.
    - Set up standalone web server.
    - Create domain private key and CSR.
    - Issue certificate.
    - Change contact information.
    - Renew Certificate
    - Revoke Certificate
    - Deactivate Account

    """
    logging.info('Example Challenge HTTP01')

    client_acme = generate_client_account_key()

    logging.info('Terms of Service URL: %s',
                 client_acme.directory.meta.terms_of_service)

    # Registration Resource: regr
    # Creates account with contact information.
    email = ('fake@emailtest.com')
    regr = client_acme.new_account(
        messages.NewRegistration.from_data(
            email=email, terms_of_service_agreed=True))

    logging.info('Account registered.')

    pkey_pem, csr_pem = new_csr_comp(DOMAIN)
    orderr = client_acme.new_order(csr_pem)

    challb = select_http01_chall(orderr)

    # The certificate is ready to be used in the variable "fullchain_pem".
    fullchain_pem = perform_http01(client_acme, challb, orderr)

    logging.info('Certificate issued: \n%s', fullchain_pem)

    regr = verify_registration(client_acme, regr)

    # Change contact information
    email = 'newfake@emailtest.com'
    regr = client_acme.update_registration(
        regr.update(
            body=regr.body.update(
                contact=('mailto:' + email,)
            )
        )
    )
    logging.info('New contact info: %s', repr(regr.body.contact))

    logging.info('Renew Certificate')

    _, csr_pem = new_csr_comp(DOMAIN, pkey_pem)

    orderr = client_acme.new_order(csr_pem)

    challb = select_http01_chall(orderr)

    logging.info('Performing challenge')

    fullchain_pem = perform_http01(client_acme, challb, orderr)

    logging.info('Certificate renewed: \n%s', fullchain_pem)

    logging.info('Revoke and Deactivate')

    fullchain_com = jose.ComparableX509(
        OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, fullchain_pem))

    try:
        client_acme.revoke(fullchain_com, 0)  # revocation reason = 0
    except errors.ConflictError:
        logging.info('Certificate already revoked.')
    else:
        logging.info('Successfully revoked cert.')

    # Deactivate registration
    regr = client_acme.deactivate_registration(regr)
    logging.info('Successfully deactivated account.')


if __name__ == "__main__":
    example_http()
