"""Example ACME API for HTTP-01 challenge.

Copyright 2017 Juliana Rodrigueiro

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

This example requires a Boulder CA server running, possibly locally.
Instructions to set up: https://github.com/letsencrypt/boulder
Run server with the argument FAKE_DNS, so any domain name will be accepted.
# docker-compose run -e FAKE_DNS=<client-ip> --service-ports boulder ./start.py

Limitations of this example:
    - Works for only one Domain name.
    - Performs only HTTP-01 challenge.

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
import os

from contextlib import contextmanager
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
import OpenSSL

from acme import challenges
from acme import client
from acme import crypto_util
from acme import errors
from acme import fields
from acme import messages
from acme import standalone

# Constants:

# IP of the machine running Boulder.
BOULDER_SERVER_IP = '172.16.1.111'

# Boulder binds by default to port 4000.
BOULDER_SERVER_PORT = 4000

SERVER_URL = 'http://' + BOULDER_SERVER_IP + ':' + repr(BOULDER_SERVER_PORT)
DIRECTORY_URL = SERVER_URL + '/directory'

USER_AGENT = 'python-acme-example'

# Account key size
ACC_KEY_BITS = 2048

# Certificate private key size
CERT_PKEY_BITS = 2048

# Domain name for the certificate.
DOMAIN = 'client.example.com'

# The Boulder fake CA tries to connect by default through the port number 5002,
# so this is where the standalone web server has to bind to. Real CA servers
# will always use port 80, though.
PORT = 5002

ACC_FILEPATH = os.path.join('/tmp', DOMAIN + '-account.json')
REGR_FILEPATH = os.path.join('/tmp', DOMAIN + '-regr.json')
PKEY_FILEPATH = os.path.join('/tmp', DOMAIN + '-pkey.pem')
CERT_FILEPATH = os.path.join('/tmp', DOMAIN + '-cert.pem')
CHAIN_FILEPATH = os.path.join('/tmp', DOMAIN + '-fullchain.pem')

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
    # Here we generate a ClientNetwork with customized user_agent, otherwise
    # the 'net' argument could have been omitted.
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    return client.Client(DIRECTORY_URL, acc_key, net=net)


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
    csr_comp = jose.ComparableX509(
        OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, csr_pem))
    return csr_comp, pkey_pem


def deactivate_authorization(client_acme, authz):
    """Deactivate an authorization resource."""
    class DeactivateAuthzResource(messages.Resource):
        resource = fields.Resource('authz')
        status = jose.Field('status', default='deactivated')

    response = client_acme.net.post(authz.uri, DeactivateAuthzResource())


def save_data(regr, client_acme, pkey_pem, cert_res):
    """Persist data."""

    if regr is not None:
        # Registration resource
        with open(REGR_FILEPATH, 'w') as regr_fd:
            regr_fd.write(regr.json_dumps())

    if client_acme is not None:
        # Account Key
        with open(ACC_FILEPATH, 'w') as acc_fd:
            acc_fd.write(client_acme.key.json_dumps())

    if pkey_pem is not None:
        # Private Key
        with open(PKEY_FILEPATH, 'wb') as pkey_fd:
            pkey_fd.write(pkey_pem)

    if cert_res is not None:
        # Certificate
        with open(CERT_FILEPATH, 'wb') as cert_fd:
            cert_fd.write(
                OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, cert_res.body.wrapped))
            logging.info('Certificate saved at %s', CERT_FILEPATH)

        # Chain
        chain = client_acme.fetch_chain(cert_res)
        with open(CHAIN_FILEPATH, 'wb') as chain_fd:
            for item in chain:
                chain_fd.write(
                    OpenSSL.crypto.dump_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, item))


def load_data():
    """Recover data from disk."""
    client_acme = create_client(load_accountkey(ACC_FILEPATH))
    regr = load_registration(REGR_FILEPATH)
    pkey = load_privatekey(PKEY_FILEPATH)
    cert = jose.ComparableX509(load_certificate(CERT_FILEPATH))
    # chain is not loaded since it is not used in any of the examples.

    return client_acme, regr, pkey, cert


def load_accountkey(filepath):
    with open(filepath, 'r') as account_fd:
        return jose.JWK.json_loads(account_fd.read())


def load_registration(filepath):
    with open(filepath, 'r') as regr_fd:
        return messages.RegistrationResource.json_loads(regr_fd.read())


def load_certificate(filepath):
    with open(filepath, 'rb') as pem_fd:
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                               pem_fd.read())


def load_privatekey(filepath):
    with open(filepath, 'rb') as pem_fd:
        return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                              pem_fd.read())


def verify_registration(client_acme, regr):
    """Query registration status."""
    try:
        return client_acme.query_registration(regr)
    except errors.Error as err:
        if err.typ == messages.OLD_ERROR_PREFIX + 'unauthorized' \
                or err.typ == messages.ERROR_PREFIX + 'unauthorized':
            logging.info('Status is deactivated')
        raise


def verify_account(client_acme):
    """Verify if account is already registered with the server."""
    # Boulder diverges from the protocol in some points listed in (https://
    # github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md):
    # "Boulder does not implement the only-return-existing behaviour and "
    # will always create a new account if an account for the given key does
    # not exist."
    try:
        new_regr = client_acme.register()
    except errors.ConflictError:
        logging.info('Account already exist')
    else:
        client_acme.deactivate_registration(new_regr)
        raise Exception('Account should already exist in the server')


def select_http01_chall(client_acme):
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz = client_acme.request_domain_challenges(DOMAIN)

    # Choosing challenge.
    # authz.body.challenges is a set of ChallengeBody objects.
    for i in authz.body.challenges:
        # Find the supported challenge.
        if isinstance(i.chall, challenges.HTTP01):
            return authz, i

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


def perform_http01(client_acme, authz, challb, csr_comp):
    """Set up standalone webserver and perform HTTP-01 challenge."""

    response, validation = challb.response_and_validation(client_acme.key)

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
                                      client_acme.key.public_key(),
                                      PORT):
            raise Exception('Verification failed')

        # Let the CA server know that we are ready for the challenge.
        client_acme.answer_challenge(challb, response)

        # Wait for challenge status and then issue a certificate.
        # cert_res = Certificate Resource
        # It is possible to set max retries and min time.
        cert_res, _ = client_acme.poll_and_request_issuance(csr_comp, [authz])

    return cert_res


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
    - Save certificate and account to disk.

    """
    logging.info('Example Challenge HTTP01')

    client_acme = generate_client_account_key()

    # Registration Resource: regr
    # Creates account with contact information.
    email = 'fake@example.com'
    regr = client_acme.register(
        messages.NewRegistration.from_data(
            email=email))

    logging.info('Account registered.')

    # Updating the registration
    regr = client_acme.agree_to_tos(regr)

    logging.info('Terms of Service URL: %s', regr.terms_of_service)

    authz, challb = select_http01_chall(client_acme)

    csr_comp, pkey_pem = new_csr_comp(DOMAIN)

    cert_res = perform_http01(client_acme, authz, challb, csr_comp)

    save_data(regr, client_acme, pkey_pem, cert_res)


def example_edit_account():
    """This example edits the contact information of an account.

    The workflow consists of:
    - Load data from disk
    - Verify that account exist in the server
    - Change contact information
    - Save data to disk

    """
    logging.info('Example Edit Account Info')

    client_acme, regr, _, _ = load_data()

    verify_account(client_acme)

    regr = verify_registration(client_acme, regr)

    # Change contact information
    email = 'newfake@example.com'
    regr = client_acme.update_registration(
        regr.update(
            body=regr.body.update(
                contact=('mailto:' + email,)
            )
        )
    )
    logging.info('New contact info: %s', repr(regr.body.contact))

    save_data(regr, client_acme, None, None)


def example_renew_cert():
    """This example renews an existing certificate.

    The workflow consists of:
    - Load data from disk
    - Verify that account exist in the server
    - Select HTTP-01 within offered challenges by the CA server.
    - Set up standalone web server
    - Reuse cert private key to generate CSR
    - Renew Certificate
    - Save certificate and account to disk.

    """
    logging.info('Example Renew Certificate')

    client_acme, regr, pkey, _ = load_data()

    verify_account(client_acme)

    regr = verify_registration(client_acme, regr)

    authz, challb = select_http01_chall(client_acme)

    pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM,
                                              pkey)
    csr_comp, _ = new_csr_comp(DOMAIN, pkey_pem)

    # When the authorization is still valid it is not necessary to fulfil a
    # challenge in order to obtain a new certificate.
    if challb.status is messages.STATUS_VALID:
        logging.info('Status is valid')
        cert_res, _ = client_acme.poll_and_request_issuance(csr_comp, [authz])
    else:
        logging.info('Performing challenge')
        cert_res = perform_http01(client_acme, authz, challb, csr_comp)

    save_data(regr, client_acme, pkey_pem, cert_res)


def example_revoke_deactivate():
    """This example revokes a certificate, deactivates an account and a
    authorization resource.

    The workflow consists of:
    - Load data from disk
    - Verify that account exist in the server
    - Revoke Certificate
    - Deactivate Authorization
    - Deactivate Account

    """
    logging.info('Example Revoke and Deactivate')

    client_acme, regr, _, cert = load_data()

    verify_account(client_acme)

    regr = verify_registration(client_acme, regr)

    try:
        client_acme.revoke(cert, 0)  # revocation reason = 0
    except errors.ConflictError:
        logging.info('Certificate already revoked.')
    else:
        logging.info('Successfully revoked cert.')

    # Deactivate Authorization
    authz = client_acme.request_domain_challenges(DOMAIN)
    deactivate_authorization(client_acme, authz)
    logging.info('Successfully deactivated authorization.')

    # Deactivate registration
    regr = client_acme.deactivate_registration(regr)
    logging.info('Successfully deactivated account.')


if __name__ == "__main__":
    example_http()
    example_edit_account()
    example_renew_cert()
    example_revoke_deactivate()
