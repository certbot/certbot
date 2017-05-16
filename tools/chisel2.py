"""
A simple client that uses the Python ACME library to run a test issuance against
a local Boulder server. Usage:

$ virtualenv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
$ python chisel.py foo.com bar.com
"""
import json
import logging
import os
import sys
import signal
import threading
import time
import urllib2

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import OpenSSL

from acme import challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import jose
from acme import messages
from acme import standalone

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(int(os.getenv('LOGLEVEL', 0)))

DIRECTORY = os.getenv('DIRECTORY', 'http://localhost:14000/dir')
#DIRECTORY = os.getenv('DIRECTORY', 'http://localhost:4000/directory')

def make_client(email=None):
    """Build an acme.Client and register a new account with a random key."""
    key = jose.JWKRSA(key=rsa.generate_private_key(65537, 2048, default_backend()))

    net = acme_client.ClientNetwork(key, verify_ssl=False,
                                    user_agent="Boulder integration tester")

    client = acme_client.Client(DIRECTORY, key=key, net=net)
    tos = client.directory.meta.terms_of_service
    if tos is not None and "Do%20what%20thou%20wilt" in tos:
        net.account = client.register(messages.NewRegistration.from_data(email=email,
            terms_of_service_agreed=True))
    else:
        raise Exception("Unrecognized terms of service URL %s" % tos)
    return client

def get_chall(authz, typ):
    for chall_body in authz.body.challenges:
        if isinstance(chall_body.chall, typ):
            return chall_body
    raise "No %s challenge found" % typ

class ValidationError(Exception):
    """An error that occurs during challenge validation."""
    def __init__(self, domain, problem_type, detail, *args, **kwargs):
        self.domain = domain
        self.problem_type = problem_type
        self.detail = detail

    def __str__(self):
        return "%s: %s: %s" % (self.domain, self.problem_type, self.detail)

def make_csr(domains):
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    csr = OpenSSL.crypto.X509Req()
    csr.add_extensions([
        OpenSSL.crypto.X509Extension(
            'subjectAltName',
            critical=False,
            value=', '.join('DNS:' + d for d in domains).encode()
        ),
    ])
    csr.set_pubkey(pkey)
    csr.set_version(2)
    csr.sign(pkey, 'sha256')
    return OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)

def issue(client, authzs, cert_output=None):
    """Given a list of authzs that are being processed by the server,
       wait for them to be ready, then request issuance of a cert with a random
       key for the given domains.

       If cert_output is provided, write the cert as a PEM file to that path."""
    csr = make_csr([authz.body.identifier.value for authz in authzs])

    cert_resource = None
    try:
        cert_resource, _ = client.poll_and_request_issuance(jose.ComparableX509(csr), authzs)
    except acme_errors.PollError as error:
        # If we get a PollError, pick the first failed authz and turn it into a more
        # useful ValidationError that contains details we can look for in tests.
        for authz in error.updated:
            updated_authz = json.loads(urllib2.urlopen(authz.uri).read())
            domain = authz.body.identifier.value,
            for c in updated_authz['challenges']:
                if 'error' in c:
                    err = c['error']
                    raise ValidationError(domain, err['type'], err['detail'])
        # If none of the authz's had an error, just re-raise.
        raise
    if cert_output is not None:
        pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                              cert_resource.body)
        with open(cert_output, 'w') as f:
            f.write(pem)
    return cert_resource

def http_01_answer(client, chall_body):
    """Return an HTTP01Resource to server in response to the given challenge."""
    response, validation = chall_body.response_and_validation(client.key)
    return standalone.HTTP01RequestHandler.HTTP01Resource(
          chall=chall_body.chall, response=response,
          validation=validation)

def auth_and_issue(domains, chall_type="http-01", email=None, cert_output=None, client=None):
    """Make authzs for each of the given domains, set up a server to answer the
       challenges in those authzs, tell the ACME server to validate the challenges,
       then poll for the authzs to be ready and issue a cert."""
    if client is None:
        client = make_client(email)

    csr_pem = make_csr(domains)
    order = client.new_order(csr_pem)
    authzs = order.authorizations

    if chall_type == "http-01":
        cleanup = do_http_challenges(client, authzs)
    #elif chall_type == "dns-01":
        #cleanup = do_dns_challenges(client, authzs)
    else:
        raise Exception("invalid challenge type %s" % chall_type)

    try:
        while True:
            order, response = client.poll_order(order)
            print order.to_json()
            if order.body.status != "pending":
                break
            time.sleep(1)
    finally:
        cleanup()

def do_dns_challenges(client, authzs):
    for a in authzs:
        c = get_chall(a, challenges.DNS01)
        name, value = (c.validation_domain_name(a.body.identifier.value),
            c.validation(client.key))
        urllib2.urlopen("http://localhost:8055/set-txt",
            data=json.dumps({
                "host": name + ".",
                "value": value,
            })).read()
        client.answer_challenge(c, c.response(client.key))
    def cleanup():
        pass
    return cleanup

def do_http_challenges(client, authzs):
    port = 5002
    challs = [get_chall(a, challenges.HTTP01) for a in authzs]
    answers = set([http_01_answer(client, c) for c in challs])
    server = standalone.HTTP01Server(("", port), answers)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    # cleanup has to be called on any exception, or when validation is done.
    # Otherwise the process won't terminate.
    def cleanup():
        server.shutdown()
        server.server_close()
        thread.join()

    try:
        # Loop until the HTTP01Server is ready.
        while True:
            try:
                urllib2.urlopen("http://localhost:%d" % port)
                break
            except urllib2.URLError:
                time.sleep(0.1)

        for chall_body in challs:
            client.answer_challenge(chall_body, chall_body.response(client.key))
    except Exception:
        cleanup()
        raise

    return cleanup

def expect_problem(problem_type, func):
    """Run a function. If it raises a ValidationError or messages.Error that
       contains the given problem_type, return. If it raises no error or the wrong
       error, raise an exception."""
    ok = False
    try:
        func()
    except ValidationError as e:
        if e.problem_type == problem_type:
            ok = True
        else:
            raise
    except messages.Error as e:
        if problem_type in e.__str__():
            ok = True
        else:
            raise
    if not ok:
        raise Exception('Expected %s, got no error' % problem_type)

if __name__ == "__main__":
    # Die on SIGINT
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    domains = sys.argv[1:]
    if len(domains) == 0:
        print __doc__
        sys.exit(0)
    try:
        auth_and_issue(domains)
    except messages.Error, e:
        print e
        sys.exit(1)
