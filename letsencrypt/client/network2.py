"""Networking for ACME protocol v02."""
import httplib
import logging

import requests

import M2Crypto

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

    def _get(self, uri, **kwargs):
        """Send GET request.

        :raises letsencrypt.client.errors.NetworkError:

        :returns: HTTP Response
        :rtype: `requests.Response`

        """
        try:
            return requests.get(uri, **kwargs)
        except requests.exception.RequestException as error:
            raise errors.NetworkError(error)

    def _post(self, uri, data, content_type='application/json', **kwargs):
        """Send POST data.

        :param str content_type: Expected Content-Type, fails if not set.

        :raises letsencrypt.acme.messages2.NetworkError:

        :returns: HTTP Response
        :rtype: `requests.Response`

        """
        logging.debug('Sending POST data: %s', data)
        try:
            response = requests.post(uri, data=data, **kwargs)
        except requests.exception.RequestException as error:
            raise errors.NetworkError(error)
        logging.debug('Received response %s: %s', response, response.text)

        if not response.ok:
            if response.content_type == 'application/json':
                raise messages2.Error.from_json(response.json())
            else:
                raise errors.NetworkError(response)

        # TODO: Boulder messes up Content-Type #56
        #if response.headers['content-type'] != content_type:
        #    raise errors.NetworkError(
        #        'Server returned unexpected content-type header')

        return response

    def _regr_from_response(self, response, uri=None, new_authz_uri=None):
        terms_of_service = (
            response.links['next']['url']
            if 'terms-of-service' in response.links else None)

        if new_authz_uri is None:
            try:
                new_authz_uri = response.links['next']['url']
            except KeyError:
                raise errors.NetworkError('"next" link missing')

        return messages2.RegistrationResource(
            body=messages2.Registration.from_json(response.json()),
            uri=response.headers.get('location', uri),
            new_authz_uri=new_authz_uri,
            terms_of_service=terms_of_service)

    def register(self, contact=messages2.Registration._fields['contact'].default):
        """Register.

        :returns: Registration Resource.
        :rtype: `.RegistrationResource`

        :raises letsencrypt.client.errors.UnexpectedUpdate:

        """
        new_reg = messages2.Registration(contact=contact)

        response = self._post(self.new_reg_uri, self._wrap_in_jws(new_reg))
        assert response.status_code == httplib.CREATED  # TODO: handle errors

        regr = self._regr_from_response(response)
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

        # TODO: Boulder returns httplib.ACCEPTED
        #assert response.status_code == httplib.OK

        # TODO: Boulder does not set Location or Link on update
        # (c.f. acme-spec #94)

        updated_regr = self._regr_from_response(
            response, uri=regr.uri, new_authz_uri=regr.new_authz_uri)
        if updated_regr != regr:
            pass
            # TODO: Boulder reregisters with new recoveryToken and new URI
            #raise errors.UnexpectedUpdate(regr)
        return updated_regr

    def _authzr_from_response(self, response, identifier,
                              uri=None, new_cert_uri=None):
        if new_cert_uri is None:
            try:
                new_cert_uri = response.links['next']['url']
            except KeyError:
                raise errors.NetworkError('"next" link missing')

        authzr = messages2.AuthorizationResource(
            body=messages2.Authorization.from_json(response.json()),
            uri=response.headers.get('location', uri),
            new_cert_uri=new_cert_uri)
        if (authzr.body.key != self.key.public()
                or authzr.body.identifier != identifier):
            raise errors.UnexpectedUpdate(authzr)
        return authzr

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
        return self._authzr_from_response(response, identifier)

    # TODO: anything below is also stub, bot not working, not tested at all

    def answer_challenge(self, challr, response):
        """Answer challenge.

        :param challr: Corresponding challenge resource.
        :type challr: `.ChallengeResource`

        :param response: Challenge response
        :type response: `.challenges.ChallengeResponse`

        :returns: Updated challenge resource.
        :rtype: `.ChallengeResource`

        :raises errors.UnexpectedUpdate:

        """
        response = self._post(challr.uri, self._wrap_in_jws(response))
        if response.headers['location'] != challr.uri:
            raise UnexpectedUpdate(response.headers['location'])
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
        response = self._get(authzr.uri)
        retry_after = 0  # TODO, get it from response.headers.get('Retry-After')

        updated_authzr = self._authzr_from_response(
            response, authzr.body.identifier, authzr.uri, authzr.new_cert_uri)
        # TODO check UnexpectedUpdate

        return updated_authzr, retry_after

    def request_issuance(self, csr, authzrs):
        """Request issuance.

        :param csr: CSR
        :type csr: `M2Crypto.X509.Request`

        :param authzrs: `list` of `.AuthorizationResource`

        """
        # TODO: assert len(authzrs) == number of SANs
        req = messages2.CertificateRequest(
            csr=csr, authorizations=tuple(authzr.uri for authzr in authzrs))
        response = self._post(
            authzrs[0].new_cert_uri,  # TODO: acme-spec #90
            self._wrap_in_jws(req))
        # assert content-type: application/pkix-cert
        return messages2.CertificateResource(
            authzrs=authzrs,
            body=M2Crypto.X509.load_cert_der_string(response.text),
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
        return self._get(certr.uri)

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
