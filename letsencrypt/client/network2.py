"""Networking for ACME protocol v02."""
import httplib
import logging

import requests

from letsencrypt.acme import jose
from letsencrypt.acme import messages2

from letsencrypt.client import errors


class Network(object):
    """ACME networking.

    :ivar str new_reg_uri: Location of new-reg
    :ivar key: `.JWK` (private)
    :ivar alg: `.JWASignature`

    """

    def __init__(self, new_reg_uri, key, alg=jose.RS256):
        self.new_reg_uri = new_reg_uri
        self.key = key
        self.alg = alg

    def _wrap_in_jws(self, data):
        dumps = data.json_dumps()
        logging.debug('Serialized JSON: %s', dumps)
        return jose.JWS.sign(
            payload=dumps, key=self.key, alg=self.alg).json_dumps()

    def _post(self, uri, data):
        logging.debug('Sending data: %s', data)
        response = requests.post(uri, data)
        logging.debug('Received response %s: %s', response, response.text)
        return response

    def register(self, contact=messages2.Registration._fields['contact'].default):
        """Register.

        :returns: Registration Resource.
        :rtype: `.RegistrationResource`

        :raises letsencrypt.client.errors.UnexpectedUpdate:

        """
        new_reg = messages2.Registration(contact=contact)

        response = self._post(self.new_reg_uri, self._wrap_in_jws(new_reg))
        assert response.status_code == httplib.CREATED  # TODO: handle errors

        terms_of_service = (response.links['next']['url']
               if 'terms-of-service' in response.links else None)
        regr = messages2.RegistrationResource(
            body=messages2.Registration.from_json(response.json()),
            uri=response.headers['location'],
            new_authz_uri=response.links['next']['url'],
            terms_of_service=terms_of_service)

        if regr.body.key != self.key.public() or regr.body.contact != contact:
            raise errors.UnexpectedUpdate(regr)

        return regr

    def update_registration(self, regr):
        """Update registration.

        :pram regr: Registration Resource.
        :type regr: `.RegistrationResource`

        :returns: Updated Registration Resource.
        :rtype: `.RegistrationResource`

        """
        response = self._post(regr.uri, self._wrap_in_jws(regr.body))

    def request_challenges(self, identifier, regr):
        """Request challenges.

        :param identifier: Identifier to be challenged.
        :type identifier: `.messages2.Identifier`

        :pram regr: Registration resource.
        :type regr: `.RegistrationResource`

        """
        new_authz = messages2.Authorization(identifier=identifier)
        response = self._post(regr.new_authz_uri, self._wrap_in_jws(new_authz))
        assert response.status_code == httplib.CREATED  # TODO: handle errors
        authzr = messages2.AuthorizationResource(
            body=messages2.Authorization.from_json(response.json()),
            uri=response.headers['location'],
            new_cert_uri=response.links['next']['url'])
        assert authzr.body.key == self.key.public()
        return authzr

    # TODO: anything below is also stub, bot not working, not tested at all

    def answer_challenge(self, challr, response):
        """Answer challenge.

        :param challr: Corresponding challenge resource.
        :type challr: `.ChallengeResource`

        :param response: Challenge response
        :type response: `.challenges.ChallengeResponse`

        :returns: Updated challenge resource.
        :rtype: `.ChallengeResource`

        """
        response = self._post(challr.uri, self._wrap_in_jws(response))
        assert response.headers['location'] == challr.uri
        updated_challr = messages2.ChallengeResource(
            body=challenges.Challenge.from_json(response.json()),
            uri=challr.uri)
        return updated_challr

    def answer_challenges(self, challrs, responses):
        """Answer multiple challenges.

        .. note:: This is a convenience function to make integration
           with old proto code easier and shall probably be removed
           once restification is over.

        """
        return [self.answer_challenge(challr, response)
                for challr, response in itertools.izip(challrs, responses)]

    def poll(self, authzr):
        """Poll Authorization Resource for status.

        :param authzr: Authorization Resource
        :type authzr: `.AuthorizationResource`

        :returns: Updated Authorization Resource and 'Retry-After'
            value (0, if such header not provided).

        :rtype: (`.AuthorizationResource`, `int`)

        """

    def request_issuance(self, csr, authzrs):
        """Request issuance.

        :param csr: CSR
        :type csr: `M2Crypto.X509.Request`

        :param authzrs: `list` of `.AuthorizationResource`

        """
        req = CertificateRequest(
            csr=csr, authorizations=tuple(authzr.uri for authzr in authzrs))
        response = self._post(
            authzrs[0].new_cert_uri,  # TODO: acme-spec #90
            self._wrap_in_jws(req))
        # assert content-type: application/pkix-cert
        return messages2.CertificateResource(
            authzrs=authzrs,
            body=M2Crypto.X509.load_der_string(response.text),
            cert_chain_uri=response.links['up']['url'])

    def poll_and_request_issuance(self, csr, authzrs, mintime=5):
        """Poll and request issuance.

        :param int mintime: Minimum time before next attempt

        """
        waiting = set()
        finished = set()

        while waiting:
            authzr = waiting.pop()
            updated_authzr, retry_after = self.poll(authzr)
            if updated_authzr.body.status == messages2.StatusValidated:
                finished.add(updated_authzr)
            else:
                waiting.add(updated_authzr)
            # TODO: implement reasonable sleeping!

        return request_issuance(csr, authzrs)

    def check_cert(self, certr):
        """Check for new cert.

        :param certr: Certificate Resource
        :type certr: `.CertificateResource`

        """
        # TODO: acme-spec 5.1 table action should be renamed to
        # "refresh cert", and this method integrated with self.refresh
        return requests.get(certr.uri)

    def refresh(self, certr):
        """Refresh certificate."""
        return self.check_cert(certr)

    def fetch_chain(self, certr):
        """Fetch chain for certificate."""

    def revoke(self, certr, when='now'):
        """Revoke certificate.

        :param when: When should the revocation take place.
        :type when: `.Revocation.When`

        """
        rev = messages2.Revocation(revoke=when, authorizations=tuple(
            authzr.uri for authzr in certr.authzrs))
