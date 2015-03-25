"""Networking for ACME protocol v02."""
import datetime
import heapq
import httplib
import logging
import time

import requests
import werkzeug

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

    DER_CONTENT_TYPE = 'application/plix-cert'

    def __init__(self, new_reg_uri, key, alg=jose.RS256):
        self.new_reg_uri = new_reg_uri
        self.key = key
        self.alg = alg

    def _wrap_in_jws(self, data):
        """Wrap `JSONDeSerializable` object in JWS."""
        dumps = data.json_dumps()
        logging.debug('Serialized JSON: %s', dumps)
        return jose.JWS.sign(
            payload=dumps, key=self.key, alg=self.alg).json_dumps()

    def _check_content_type(self, response, content_type):
        # TODO: Boulder messes up Content-Type #56
        #if response.headers['content-type'] != content_type:
        #    raise errors.NetworkError(
        #        'Server returned unexpected content-type header')
        pass

    def _get(self, uri, content_type='application/json', **kwargs):
        """Send GET request.

        :raises letsencrypt.client.errors.NetworkError:

        :returns: HTTP Response
        :rtype: `requests.Response`

        """
        try:
            response = requests.get(uri, **kwargs)
        except requests.exception.RequestException as error:
            raise errors.NetworkError(error)
        self._check_content_type(response, content_type)
        return response

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
            # Boulder messes up Content-Type #56
            #if response.headers['content-type'] == 'application/json':
            raise messages2.Error.from_json(response.json())
            #else:
            #    raise errors.NetworkError(response)

        self._check_content_type(response, content_type)
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
        updated_challr = challr.update(
            body=challenges.Challenge.from_json(response.json()))
        return updated_challr

    def answer_challenges(self, challrs, responses):
        """Answer multiple challenges.

        .. note:: This is a convenience function to make integration
           with old proto code easier and shall probably be removed
           once restification is over.

        """
        return [self.answer_challenge(challr, response)
                for challr, response in itertools.izip(challrs, responses)]

    def _retry_after(self, response, mintime):
        ra = response.headers.get('Retry-After', str(mintime))
        try:
            seconds = int(ra)
        except ValueError:
            return werkzeug.parse_date(ra)
        else:
            return datetime.datetime.now() + datetime.timedelta(seconds=seconds)

    def poll(self, authzr):
        """Poll Authorization Resource for status.

        :param authzr: Authorization Resource
        :type authzr: `.AuthorizationResource`

        :returns: Updated Authorization Resource and HTTP response.

        :rtype: (`.AuthorizationResource`, `requests.Response`)

        """
        response = self._get(authzr.uri)
        updated_authzr = self._authzr_from_response(
            response, authzr.body.identifier, authzr.uri, authzr.new_cert_uri)
        # TODO check UnexpectedUpdate

        return updated_authzr, response

    def request_issuance(self, csr, authzrs):
        """Request issuance.

        :param csr: CSR
        :type csr: `M2Crypto.X509.Request`

        :param authzrs: `list` of `.AuthorizationResource`

        """
        # TODO: assert len(authzrs) == number of SANs
        req = messages2.CertificateRequest(
            csr=csr, authorizations=tuple(authzr.uri for authzr in authzrs))

        content_type = self.DER_CONTENT_TYPE  # TODO: add 'cert_type 'argument
        response = self._post(
            authzrs[0].new_cert_uri,  # TODO: acme-spec #90
            self._wrap_in_jws(req),
            content_type=content_type,
            headers={'Accept': content_type})

        return messages2.CertificateResource(
            authzrs=authzrs,
            body=M2Crypto.X509.load_cert_der_string(response.text),
            cert_chain_uri=response.links['up']['url'])

    def poll_and_request_issuance(self, csr, authzrs, mintime=5):
        """Poll and request issuance.

        :param int mintime: Minimum time before next attempt.

        .. todo:: add `max_attempts` or `timeout`

        """
        # priority queue with datetime (based od Retry-After) as key,
        # and original Authorization Resource as value
        waiting = [(datetime.datetime.now(), authzr) for authzr in authzrs]
        # mapping between original Authorization Resource and the most
        # recently updated one
        updated = dict((authzr, authzr) for authzr in authzrs)

        while waiting:
            # find the smallest Retry-After, and sleep if necessary
            when, authzr = heapq.heappop(waiting)
            now = datetime.datetime.now()
            if when > now:
                seconds = (when - now).seconds
                logging.debug('Sleeping for %d seconds', seconds)
                time.sleep(seconds)

            updated_authzr, response = self.poll(authzr)
            updated[authzr] = updated_authzr
            # URI must not change throughout, as we are polling
            # original Authorization Resource URI only
            assert updated_authzr.uri == authzr

            if updated_authzr.body.status != messages2.StatusValidated:
                # push back to the priority queue, with updated retry_after
                heapq.heappush(waiting, (self._retry_after(
                    response, mintime=mintime), authzr))

        return request_issuance(csr, authzrs), tuple(
            updated[authzr] for authzr in authzrs)

    def _get_cert(self, uri):
        content_type = self.DER_CONTENT_TYPE  # TODO: make it a param
        response = self._get(uri, headers={'Accept': content_type},
                             content_type=content_type)
        return response, M2Crypto.X509.load_cert_der_string(response.text)

    def check_cert(self, certr):
        """Check for new cert.

        :param certr: Certificate Resource
        :type certr: `.CertificateResource`

        :returns: Updated Certificate Resource.
        :rtype: `.CertificateResource`

        """
        # TODO: acme-spec 5.1 table action should be renamed to
        # "refresh cert", and this method integrated with self.refresh
        response, cert = self._get_cert(certr.uri)
        if not response.headers['location'] != certr.uri:
            raise UnexpectedUpdate(response.text)
        return certr.update(body=cert)

    def refresh(self, certr):
        """Refresh certificate.

        :param certr: Certificate Resource
        :type certr: `.CertificateResource`

        :returns: Updated Certificate Resource.
        :rtype: `.CertificateResource`

        """
        return self.check_cert(certr)

    def fetch_chain(self, certr):
        """Fetch chain for certificate.

        :param certr: Certificate Resource
        :type certr: `.CertificateResource`

        :returns: Certificate chain
        :rtype: `M2Crypto.X509.X509`

        """
        return self._get_cert(certr.cert_chain_uri)

    def revoke(self, certr, when='now'):
        """Revoke certificate.

        :param when: When should the revocation take place.
        :type when: `.Revocation.When`

        """
        rev = messages2.Revocation(revoke=when, authorizations=tuple(
            authzr.uri for authzr in certr.authzrs))
        response = self._post(certr.uri, self._wrap_in_jws(rev))
        if response.status_code != httplib.OK:
            raise errors.NetworkError(
                'Successful revocation must return HTTP OK status')
