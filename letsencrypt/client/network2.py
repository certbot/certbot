"""Networking for ACME protocol v02."""
import datetime
import heapq
import httplib
import logging
import time

import M2Crypto
import requests
import werkzeug

from letsencrypt.acme import jose
from letsencrypt.acme import messages2

from letsencrypt.client import errors


# https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()


class Network(object):
    """ACME networking.

    .. todo::
       Clean up raised error types hierarchy, document, and handle (wrap)
       instances of `.DeserializationError` raised in `from_json()``.

    :ivar str new_reg_uri: Location of new-reg
    :ivar key: `.JWK` (private)
    :ivar alg: `.JWASignature`

    """

    DER_CONTENT_TYPE = 'application/pkix-cert'
    JSON_CONTENT_TYPE = 'application/json'
    JSON_ERROR_CONTENT_TYPE = 'application/problem+json'

    def __init__(self, new_reg_uri, key, alg=jose.RS256):
        self.new_reg_uri = new_reg_uri
        self.key = key
        self.alg = alg

    def _wrap_in_jws(self, obj):
        """Wrap `JSONDeSerializable` object in JWS.

        :rtype: `.JWS`

        """
        dumps = obj.json_dumps()
        logging.debug('Serialized JSON: %s', dumps)
        return jose.JWS.sign(
            payload=dumps, key=self.key, alg=self.alg).json_dumps()

    @classmethod
    def _check_response(cls, response, content_type=None):
        """Check response content and its type.

        .. note::
           Checking is not strict: wrong server response ``Content-Type``
           HTTP header is ignored if response is an expected JSON object
           (c.f. Boulder #56).

        :param str content_type: Expected Content-Type response header.
            If JSON is expected and not present in server response, this
            function will raise an error. Otherwise, wrong Content-Type
            is ignored, but logged.

        :raises letsencrypt.messages2.Error: If server response body
            carries HTTP Problem (draft-ietf-appsawg-http-problem-00).
        :raises letsencrypt.errors.NetworkError: In case of other
            networking errors.

        """
        response_ct = response.headers.get('Content-Type')
        try:
            # TODO: response.json() is called twice, once here, and
            # once in _get and _post clients
            jobj = response.json()
        except ValueError as error:
            jobj = None

        if not response.ok:
            if jobj is not None:
                if response_ct != cls.JSON_ERROR_CONTENT_TYPE:
                    logging.debug(
                        'Ignoring wrong Content-Type (%r) for JSON Error',
                        response_ct)

                try:
                    # TODO: This is insufficient or doesn't work as intended.
                    raise messages2.Error.from_json(jobj)
                except jose.DeserializationError as error:
                    # Couldn't deserialize JSON object
                    raise errors.NetworkError((response, error))
            else:
                # response is not JSON object
                raise errors.NetworkError(response)
        else:
            if jobj is not None and response_ct != cls.JSON_CONTENT_TYPE:
                logging.debug(
                    'Ignoring wrong Content-Type (%r) for JSON decodable '
                    'response', response_ct)

            if content_type == cls.JSON_CONTENT_TYPE and jobj is None:
                raise errors.NetworkError(
                    'Unexpected response Content-Type: {0}'.format(response_ct))

    def _get(self, uri, content_type=JSON_CONTENT_TYPE, **kwargs):
        """Send GET request.

        :raises letsencrypt.client.errors.NetworkError:

        :returns: HTTP Response
        :rtype: `requests.Response`

        """
        try:
            response = requests.get(uri, **kwargs)
        except requests.exceptions.RequestException as error:
            raise errors.NetworkError(error)
        self._check_response(response, content_type=content_type)
        return response

    def _post(self, uri, data, content_type=JSON_CONTENT_TYPE, **kwargs):
        """Send POST data.

        :param str content_type: Expected ``Content-Type``, fails if not set.

        :raises letsencrypt.acme.messages2.NetworkError:

        :returns: HTTP Response
        :rtype: `requests.Response`

        """
        logging.debug('Sending POST data: %s', data)
        try:
            response = requests.post(uri, data=data, **kwargs)
        except requests.exceptions.RequestException as error:
            raise errors.NetworkError(error)
        logging.debug('Received response %s: %s', response, response.text)

        self._check_response(response, content_type=content_type)
        return response

    @classmethod
    def _regr_from_response(cls, response, uri=None, new_authzr_uri=None,
                            terms_of_service=None):
        terms_of_service = (
            response.links['terms-of-service']['url']
            if 'terms-of-service' in response.links else terms_of_service)

        # TODO: Consider removing this check based on spec clarifications #93
        if new_authzr_uri is None:
            try:
                new_authzr_uri = response.links['next']['url']
            except KeyError:
                raise errors.NetworkError('"next" link missing')

        return messages2.RegistrationResource(
            body=messages2.Registration.from_json(response.json()),
            uri=response.headers.get('Location', uri),
            new_authzr_uri=new_authzr_uri,
            terms_of_service=terms_of_service)

    def register(self, contact=messages2.Registration._fields[
            'contact'].default):
        """Register.

        :param contact: Contact list, as accepted by `.Registration`
        :type contact: `tuple`

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

    def register_from_account(self, account):
        """Register with server.

        :param account: Account
        :type account: :class:`letsencrypt.client.account.Account`

        :returns: Updated account
        :rtype: :class:`letsencrypt.client.account.Account`

        """
        details = (
            "mailto:" + account.email if account.email is not None else None,
            "tel:" + account.phone if account.phone is not None else None
        )

        contact_tuple = tuple(det for det in details if det is not None)

        account.regr = self.register(contact=contact_tuple)

        return account

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
            response, uri=regr.uri, new_authzr_uri=regr.new_authzr_uri,
            terms_of_service=regr.terms_of_service)
        if updated_regr != regr:
            # TODO: Boulder reregisters with new recoveryToken and new URI
            raise errors.UnexpectedUpdate(regr)
        return updated_regr

    def agree_to_tos(self, regr):
        """Agree to the terms-of-service.

        Agree to the terms-of-service in a Registration Resource.

        :param regr: Registration Resource.
        :type regr: `.RegistrationResource`

        :returns: Updated Registration Resource.
        :rtype: `.RegistrationResource`

        """
        return self.update_registration(
            regr.update(body=regr.body.update(agreement=regr.terms_of_service)))

    def _authzr_from_response(self, response, identifier,
                              uri=None, new_cert_uri=None):
        if new_cert_uri is None:
            try:
                new_cert_uri = response.links['next']['url']
            except KeyError:
                raise errors.NetworkError('"next" link missing')

        authzr = messages2.AuthorizationResource(
            body=messages2.Authorization.from_json(response.json()),
            uri=response.headers.get('Location', uri),
            new_cert_uri=new_cert_uri)
        if (authzr.body.key != self.key.public()
                or authzr.body.identifier != identifier):
            raise errors.UnexpectedUpdate(authzr)
        return authzr

    def request_challenges(self, identifier, new_authzr_uri):
        """Request challenges.

        :param identifier: Identifier to be challenged.
        :type identifier: `.messages2.Identifier`

        :param str new_authzr_uri: new-authorization URI

        :returns: Authorization Resource.
        :rtype: `.AuthorizationResource`

        """
        new_authz = messages2.Authorization(identifier=identifier)
        response = self._post(new_authzr_uri, self._wrap_in_jws(new_authz))
        assert response.status_code == httplib.CREATED  # TODO: handle errors
        return self._authzr_from_response(response, identifier)

    def request_domain_challenges(self, domain, new_authz_uri):
        """Request challenges for domain names.

        This is simply a convenience function that wraps around
        `request_challenges`, but works with domain names instead of
        generic identifiers.

        :param str domain: Domain name to be challenged.
        :param str new_authzr_uri: new-authorization URI

        :returns: Authorization Resource.
        :rtype: `.AuthorizationResource`

        """
        return self.request_challenges(messages2.Identifier(
            typ=messages2.IDENTIFIER_FQDN, value=domain), new_authz_uri)

    def answer_challenge(self, challb, response):
        """Answer challenge.

        :param challb: Challenge Resource body.
        :type challb: `.ChallengeBody`

        :param response: Corresponding Challenge response
        :type response: `.challenges.ChallengeResponse`

        :returns: Challenge Resource with updated body.
        :rtype: `.ChallengeResource`

        :raises errors.UnexpectedUpdate:

        """
        response = self._post(challb.uri, self._wrap_in_jws(response))
        try:
            authzr_uri = response.links['up']['url']
        except KeyError:
            # TODO: Right now Boulder responds with the authorization resource
            # instead of a challenge resource... this can be uncommented
            # once the error is fixed.
            return None
            # raise errors.NetworkError('"up" Link header missing')
        challr = messages2.ChallengeResource(
            authzr_uri=authzr_uri,
            body=messages2.ChallengeBody.from_json(response.json()))
        # TODO: check that challr.uri == response.headers['Location']?
        if challr.uri != challb.uri:
            raise errors.UnexpectedUpdate(challb.uri)
        return challr

    @classmethod
    def retry_after(cls, response, default):
        """Compute next `poll` time based on response ``Retry-After`` header.

        :param response: Response from `poll`.
        :type response: `requests.Response`

        :param int default: Default value (in seconds), used when
            ``Retry-After`` header is not present or invalid.

        :returns: Time point when next `poll` should be performed.
        :rtype: `datetime.datetime`

        """
        retry_after = response.headers.get('Retry-After', str(default))
        try:
            seconds = int(retry_after)
        except ValueError:
            # pylint: disable=no-member
            decoded = werkzeug.parse_date(retry_after)  # RFC1123
            if decoded is None:
                seconds = default
            else:
                return decoded

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
        # TODO: check and raise UnexpectedUpdate

        return updated_authzr, response

    def request_issuance(self, csr, authzrs):
        """Request issuance.

        :param csr: CSR
        :type csr: `M2Crypto.X509.Request` wrapped in `.ComparableX509`

        :param authzrs: `list` of `.AuthorizationResource`

        :returns: Issued certificate
        :rtype: `.messages2.CertificateResource`

        """
        assert authzrs, "Authorizations list is empty"
        logging.debug("Requesting issuance...")

        # TODO: assert len(authzrs) == number of SANs
        req = messages2.CertificateRequest(
            csr=csr, authorizations=tuple(authzr.uri for authzr in authzrs))

        content_type = self.DER_CONTENT_TYPE  # TODO: add 'cert_type 'argument
        response = self._post(
            authzrs[0].new_cert_uri,  # TODO: acme-spec #90
            self._wrap_in_jws(req),
            content_type=content_type,
            headers={'Accept': content_type})

        cert_chain_uri = response.links.get('up', {}).get('url')

        try:
            uri = response.headers['Location']
        except KeyError:
            raise errors.NetworkError('"Location" Header missing')

        return messages2.CertificateResource(
            uri=uri, authzrs=authzrs, cert_chain_uri=cert_chain_uri,
            body=jose.ComparableX509(
                M2Crypto.X509.load_cert_der_string(response.content)))

    def poll_and_request_issuance(self, csr, authzrs, mintime=5):
        """Poll and request issuance.

        This function polls all provided Authorization Resource URIs
        until all challenges are valid, respecting ``Retry-After`` HTTP
        headers, and then calls `request_issuance`.

        .. todo:: add `max_attempts` or `timeout`

        :param csr: CSR.
        :type csr: `M2Crypto.X509.Request` wrapped in `.ComparableX509`

        :param authzrs: `list` of `.AuthorizationResource`

        :param int mintime: Minimum time before next attempt, used if
            ``Retry-After`` is not present in the response.

        :returns: ``(cert, updated_authzrs)`` `tuple` where ``cert`` is
            the issued certificate (`.messages2.CertificateResource.),
            and ``updated_authzrs`` is a `tuple` consisting of updated
            Authorization Resources (`.AuthorizationResource`) as
            present in the responses from server, and in the same order
            as the input ``authzrs``.
        :rtype: `tuple`

        """
        # priority queue with datetime (based on Retry-After) as key,
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

            # Note that we poll with the latest updated Authorization
            # URI, which might have a different URI than initial one
            updated_authzr, response = self.poll(updated[authzr])
            updated[authzr] = updated_authzr

            if updated_authzr.body.status != messages2.STATUS_VALID:
                # push back to the priority queue, with updated retry_after
                heapq.heappush(waiting, (self.retry_after(
                    response, default=mintime), authzr))

        updated_authzrs = tuple(updated[authzr] for authzr in authzrs)
        return self.request_issuance(csr, updated_authzrs), updated_authzrs

    def _get_cert(self, uri):
        """Returns certificate from URI.

        :param str uri: URI of certificate

        :returns: tuple of the form
            (response, :class:`letsencrypt.acme.jose.ComparableX509`)
        :rtype: tuple

        """
        content_type = self.DER_CONTENT_TYPE  # TODO: make it a param
        response = self._get(uri, headers={'Accept': content_type},
                             content_type=content_type)
        return response, jose.ComparableX509(
            M2Crypto.X509.load_cert_der_string(response.content))

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
        if 'Location' not in response.headers:
            raise errors.NetworkError('Location header missing')
        if response.headers['Location'] != certr.uri:
            raise errors.UnexpectedUpdate(response.text)
        return certr.update(body=cert)

    def refresh(self, certr):
        """Refresh certificate.

        :param certr: Certificate Resource
        :type certr: `.CertificateResource`

        :returns: Updated Certificate Resource.
        :rtype: `.CertificateResource`

        """
        # TODO: If a client sends a refresh request and the server is
        # not willing to refresh the certificate, the server MUST
        # respond with status code 403 (Forbidden)
        return self.check_cert(certr)

    def fetch_chain(self, certr):
        """Fetch chain for certificate.

        :param certr: Certificate Resource
        :type certr: `.CertificateResource`

        :returns: Certificate chain, or `None` if no "up" Link was provided.
        :rtype: `M2Crypto.X509.X509` wrapped in `.ComparableX509`

        """
        if certr.cert_chain_uri is not None:
            return self._get_cert(certr.cert_chain_uri)[1]

    def revoke(self, certr, when=messages2.Revocation.NOW):
        """Revoke certificate.

        :param when: When should the revocation take place? Takes
           the same values as `.messages2.Revocation.revoke`.

        """
        rev = messages2.Revocation(revoke=when, authorizations=tuple(
            authzr.uri for authzr in certr.authzrs))
        response = self._post(certr.uri, self._wrap_in_jws(rev))
        if response.status_code != httplib.OK:
            raise errors.NetworkError(
                'Successful revocation must return HTTP OK status')
