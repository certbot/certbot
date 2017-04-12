"""ACME client API."""
import base64
import collections
import datetime
from email.utils import parsedate_tz
import heapq
import logging
import time

import six
from six.moves import http_client  # pylint: disable=import-error

import OpenSSL
import requests
import sys

from acme import errors
from acme import jose
from acme import jws
from acme import messages


logger = logging.getLogger(__name__)

# Prior to Python 2.7.9 the stdlib SSL module did not allow a user to configure
# many important security related options. On these platforms we use PyOpenSSL
# for SSL, which does allow these options to be configured.
# https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
if sys.version_info < (2, 7, 9):  # pragma: no cover
    try:
        requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()  # type: ignore
    except AttributeError:
        import urllib3.contrib.pyopenssl  # pylint: disable=import-error
        urllib3.contrib.pyopenssl.inject_into_urllib3()

DEFAULT_NETWORK_TIMEOUT = 45

DER_CONTENT_TYPE = 'application/pkix-cert'


class Client(object):  # pylint: disable=too-many-instance-attributes
    """ACME client.

    .. todo::
       Clean up raised error types hierarchy, document, and handle (wrap)
       instances of `.DeserializationError` raised in `from_json()`.

    :ivar messages.Directory directory:
    :ivar key: `.JWK` (private)
    :ivar alg: `.JWASignature`
    :ivar bool verify_ssl: Verify SSL certificates?
    :ivar .ClientNetwork net: Client network. Useful for testing. If not
        supplied, it will be initialized using `key`, `alg` and
        `verify_ssl`.

    """

    def __init__(self, directory, key, alg=jose.RS256, verify_ssl=True,
                 net=None):
        """Initialize.

        :param directory: Directory Resource (`.messages.Directory`) or
            URI from which the resource will be downloaded.

        """
        self.key = key
        self.net = ClientNetwork(key, alg, verify_ssl) if net is None else net

        if isinstance(directory, six.string_types):
            self.directory = messages.Directory.from_json(
                self.net.get(directory).json())
        else:
            self.directory = directory

    @classmethod
    def _regr_from_response(cls, response, uri=None, terms_of_service=None):
        if 'terms-of-service' in response.links:
            terms_of_service = response.links['terms-of-service']['url']

        return messages.RegistrationResource(
            body=messages.Registration.from_json(response.json()),
            uri=response.headers.get('Location', uri),
            terms_of_service=terms_of_service)

    def register(self, new_reg=None):
        """Register.

        :param .NewRegistration new_reg:

        :returns: Registration Resource.
        :rtype: `.RegistrationResource`

        """
        new_reg = messages.NewRegistration() if new_reg is None else new_reg
        assert isinstance(new_reg, messages.NewRegistration)

        response = self.net.post(self.directory[new_reg], new_reg)
        # TODO: handle errors
        assert response.status_code == http_client.CREATED

        # "Instance of 'Field' has no key/contact member" bug:
        # pylint: disable=no-member
        return self._regr_from_response(response)

    def _send_recv_regr(self, regr, body):
        response = self.net.post(regr.uri, body)

        # TODO: Boulder returns httplib.ACCEPTED
        #assert response.status_code == httplib.OK

        # TODO: Boulder does not set Location or Link on update
        # (c.f. acme-spec #94)

        return self._regr_from_response(
            response, uri=regr.uri,
            terms_of_service=regr.terms_of_service)

    def update_registration(self, regr, update=None):
        """Update registration.

        :param messages.RegistrationResource regr: Registration Resource.
        :param messages.Registration update: Updated body of the
            resource. If not provided, body will be taken from `regr`.

        :returns: Updated Registration Resource.
        :rtype: `.RegistrationResource`

        """
        update = regr.body if update is None else update
        body = messages.UpdateRegistration(**dict(update))
        updated_regr = self._send_recv_regr(regr, body=body)
        return updated_regr

    def deactivate_registration(self, regr):
        """Deactivate registration.

        :param messages.RegistrationResource regr: The Registration Resource
            to be deactivated.

        :returns: The Registration resource that was deactivated.
        :rtype: `.RegistrationResource`

        """
        return self.update_registration(regr, update={'status': 'deactivated'})

    def query_registration(self, regr):
        """Query server about registration.

        :param messages.RegistrationResource: Existing Registration
            Resource.

        """
        return self._send_recv_regr(regr, messages.UpdateRegistration())

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

    def _authzr_from_response(self, response, identifier, uri=None):
        authzr = messages.AuthorizationResource(
            body=messages.Authorization.from_json(response.json()),
            uri=response.headers.get('Location', uri))
        if authzr.body.identifier != identifier:
            raise errors.UnexpectedUpdate(authzr)
        return authzr

    def request_challenges(self, identifier, new_authzr_uri=None):
        """Request challenges.

        :param .messages.Identifier identifier: Identifier to be challenged.
        :param str new_authzr_uri: Deprecated. Do not use.

        :returns: Authorization Resource.
        :rtype: `.AuthorizationResource`

        """
        if new_authzr_uri is not None:
            logger.debug("request_challenges with new_authzr_uri deprecated.")
        new_authz = messages.NewAuthorization(identifier=identifier)
        response = self.net.post(self.directory.new_authz, new_authz)
        # TODO: handle errors
        assert response.status_code == http_client.CREATED
        return self._authzr_from_response(response, identifier)

    def request_domain_challenges(self, domain, new_authzr_uri=None):
        """Request challenges for domain names.

        This is simply a convenience function that wraps around
        `request_challenges`, but works with domain names instead of
        generic identifiers. See ``request_challenges`` for more
        documentation.

        :param str domain: Domain name to be challenged.
        :param str new_authzr_uri: Deprecated. Do not use.

        :returns: Authorization Resource.
        :rtype: `.AuthorizationResource`

        """
        return self.request_challenges(messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value=domain), new_authzr_uri)

    def answer_challenge(self, challb, response):
        """Answer challenge.

        :param challb: Challenge Resource body.
        :type challb: `.ChallengeBody`

        :param response: Corresponding Challenge response
        :type response: `.challenges.ChallengeResponse`

        :returns: Challenge Resource with updated body.
        :rtype: `.ChallengeResource`

        :raises .UnexpectedUpdate:

        """
        response = self.net.post(challb.uri, response)
        try:
            authzr_uri = response.links['up']['url']
        except KeyError:
            raise errors.ClientError('"up" Link header missing')
        challr = messages.ChallengeResource(
            authzr_uri=authzr_uri,
            body=messages.ChallengeBody.from_json(response.json()))
        # TODO: check that challr.uri == response.headers['Location']?
        if challr.uri != challb.uri:
            raise errors.UnexpectedUpdate(challr.uri)
        return challr

    @classmethod
    def retry_after(cls, response, default):
        """Compute next `poll` time based on response ``Retry-After`` header.

        Handles integers and various datestring formats per
        https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.37

        :param requests.Response response: Response from `poll`.
        :param int default: Default value (in seconds), used when
            ``Retry-After`` header is not present or invalid.

        :returns: Time point when next `poll` should be performed.
        :rtype: `datetime.datetime`

        """
        retry_after = response.headers.get('Retry-After', str(default))
        try:
            seconds = int(retry_after)
        except ValueError:
            # The RFC 2822 parser handles all of RFC 2616's cases in modern
            # environments (primarily HTTP 1.1+ but also py27+)
            when = parsedate_tz(retry_after)
            if when is not None:
                try:
                    tz_secs = datetime.timedelta(when[-1] if when[-1] else 0)
                    return datetime.datetime(*when[:7]) - tz_secs
                except (ValueError, OverflowError):
                    pass
            seconds = default

        return datetime.datetime.now() + datetime.timedelta(seconds=seconds)

    def poll(self, authzr):
        """Poll Authorization Resource for status.

        :param authzr: Authorization Resource
        :type authzr: `.AuthorizationResource`

        :returns: Updated Authorization Resource and HTTP response.

        :rtype: (`.AuthorizationResource`, `requests.Response`)

        """
        response = self.net.get(authzr.uri)
        updated_authzr = self._authzr_from_response(
            response, authzr.body.identifier, authzr.uri)
        return updated_authzr, response

    def request_issuance(self, csr, authzrs):
        """Request issuance.

        :param csr: CSR
        :type csr: `OpenSSL.crypto.X509Req` wrapped in `.ComparableX509`

        :param authzrs: `list` of `.AuthorizationResource`

        :returns: Issued certificate
        :rtype: `.messages.CertificateResource`

        """
        assert authzrs, "Authorizations list is empty"
        logger.debug("Requesting issuance...")

        # TODO: assert len(authzrs) == number of SANs
        req = messages.CertificateRequest(csr=csr)

        content_type = DER_CONTENT_TYPE  # TODO: add 'cert_type 'argument
        response = self.net.post(
            self.directory.new_cert,
            req,
            content_type=content_type,
            headers={'Accept': content_type})

        cert_chain_uri = response.links.get('up', {}).get('url')

        try:
            uri = response.headers['Location']
        except KeyError:
            raise errors.ClientError('"Location" Header missing')

        return messages.CertificateResource(
            uri=uri, authzrs=authzrs, cert_chain_uri=cert_chain_uri,
            body=jose.ComparableX509(OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, response.content)))

    def poll_and_request_issuance(
            self, csr, authzrs, mintime=5, max_attempts=10):
        """Poll and request issuance.

        This function polls all provided Authorization Resource URIs
        until all challenges are valid, respecting ``Retry-After`` HTTP
        headers, and then calls `request_issuance`.

        :param .ComparableX509 csr: CSR (`OpenSSL.crypto.X509Req`
            wrapped in `.ComparableX509`)
        :param authzrs: `list` of `.AuthorizationResource`
        :param int mintime: Minimum time before next attempt, used if
            ``Retry-After`` is not present in the response.
        :param int max_attempts: Maximum number of attempts (per
            authorization) before `PollError` with non-empty ``waiting``
            is raised.

        :returns: ``(cert, updated_authzrs)`` `tuple` where ``cert`` is
            the issued certificate (`.messages.CertificateResource`),
            and ``updated_authzrs`` is a `tuple` consisting of updated
            Authorization Resources (`.AuthorizationResource`) as
            present in the responses from server, and in the same order
            as the input ``authzrs``.
        :rtype: `tuple`

        :raises PollError: in case of timeout or if some authorization
            was marked by the CA as invalid

        """
        # pylint: disable=too-many-locals
        assert max_attempts > 0
        attempts = collections.defaultdict(int)
        exhausted = set()

        # priority queue with datetime.datetime (based on Retry-After) as key,
        # and original Authorization Resource as value
        waiting = [
            (datetime.datetime.now(), index, authzr)
            for index, authzr in enumerate(authzrs)
        ]
        heapq.heapify(waiting)
        # mapping between original Authorization Resource and the most
        # recently updated one
        updated = dict((authzr, authzr) for authzr in authzrs)

        while waiting:
            # find the smallest Retry-After, and sleep if necessary
            when, index, authzr = heapq.heappop(waiting)
            now = datetime.datetime.now()
            if when > now:
                seconds = (when - now).seconds
                logger.debug('Sleeping for %d seconds', seconds)
                time.sleep(seconds)

            # Note that we poll with the latest updated Authorization
            # URI, which might have a different URI than initial one
            updated_authzr, response = self.poll(updated[authzr])
            updated[authzr] = updated_authzr

            attempts[authzr] += 1
            # pylint: disable=no-member
            if updated_authzr.body.status not in (
                    messages.STATUS_VALID, messages.STATUS_INVALID):
                if attempts[authzr] < max_attempts:
                    # push back to the priority queue, with updated retry_after
                    heapq.heappush(waiting, (self.retry_after(
                        response, default=mintime), index, authzr))
                else:
                    exhausted.add(authzr)

        if exhausted or any(authzr.body.status == messages.STATUS_INVALID
                            for authzr in six.itervalues(updated)):
            raise errors.PollError(exhausted, updated)

        updated_authzrs = tuple(updated[authzr] for authzr in authzrs)
        return self.request_issuance(csr, updated_authzrs), updated_authzrs

    def _get_cert(self, uri):
        """Returns certificate from URI.

        :param str uri: URI of certificate

        :returns: tuple of the form
            (response, :class:`acme.jose.ComparableX509`)
        :rtype: tuple

        """
        content_type = DER_CONTENT_TYPE  # TODO: make it a param
        response = self.net.get(uri, headers={'Accept': content_type},
                                content_type=content_type)
        return response, jose.ComparableX509(OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, response.content))

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
            raise errors.ClientError('Location header missing')
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

    def fetch_chain(self, certr, max_length=10):
        """Fetch chain for certificate.

        :param .CertificateResource certr: Certificate Resource
        :param int max_length: Maximum allowed length of the chain.
            Note that each element in the certificate requires new
            ``HTTP GET`` request, and the length of the chain is
            controlled by the ACME CA.

        :raises errors.Error: if recursion exceeds `max_length`

        :returns: Certificate chain for the Certificate Resource. It is
            a list ordered so that the first element is a signer of the
            certificate from Certificate Resource. Will be empty if
            ``cert_chain_uri`` is ``None``.
        :rtype: `list` of `OpenSSL.crypto.X509` wrapped in `.ComparableX509`

        """
        chain = []
        uri = certr.cert_chain_uri
        while uri is not None and len(chain) < max_length:
            response, cert = self._get_cert(uri)
            uri = response.links.get('up', {}).get('url')
            chain.append(cert)
        if uri is not None:
            raise errors.Error(
                "Recursion limit reached. Didn't get {0}".format(uri))
        return chain

    def revoke(self, cert, rsn):
        """Revoke certificate.

        :param .ComparableX509 cert: `OpenSSL.crypto.X509` wrapped in
            `.ComparableX509`

        :param int rsn: Reason code for certificate revocation.

        :raises .ClientError: If revocation is unsuccessful.

        """
        response = self.net.post(self.directory[messages.Revocation],
                                 messages.Revocation(
                                     certificate=cert,
                                     reason=rsn),
                                 content_type=None)
        if response.status_code != http_client.OK:
            raise errors.ClientError(
                'Successful revocation must return HTTP OK status')


class ClientNetwork(object):  # pylint: disable=too-many-instance-attributes
    """Client network."""
    JSON_CONTENT_TYPE = 'application/json'
    JOSE_CONTENT_TYPE = 'application/jose+json'
    JSON_ERROR_CONTENT_TYPE = 'application/problem+json'
    REPLAY_NONCE_HEADER = 'Replay-Nonce'

    def __init__(self, key, alg=jose.RS256, verify_ssl=True,
                 user_agent='acme-python', timeout=DEFAULT_NETWORK_TIMEOUT):
        self.key = key
        self.alg = alg
        self.verify_ssl = verify_ssl
        self._nonces = set()
        self.user_agent = user_agent
        self.session = requests.Session()
        self._default_timeout = timeout

    def __del__(self):
        self.session.close()

    def _wrap_in_jws(self, obj, nonce):
        """Wrap `JSONDeSerializable` object in JWS.

        .. todo:: Implement ``acmePath``.

        :param .JSONDeSerializable obj:
        :param bytes nonce:
        :rtype: `.JWS`

        """
        jobj = obj.json_dumps(indent=2).encode()
        logger.debug('JWS payload:\n%s', jobj)
        return jws.JWS.sign(
            payload=jobj, key=self.key, alg=self.alg,
            nonce=nonce).json_dumps(indent=2)

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

        :raises .messages.Error: If server response body
            carries HTTP Problem (draft-ietf-appsawg-http-problem-00).
        :raises .ClientError: In case of other networking errors.

        """
        response_ct = response.headers.get('Content-Type')
        try:
            # TODO: response.json() is called twice, once here, and
            # once in _get and _post clients
            jobj = response.json()
        except ValueError:
            jobj = None

        if not response.ok:
            if jobj is not None:
                if response_ct != cls.JSON_ERROR_CONTENT_TYPE:
                    logger.debug(
                        'Ignoring wrong Content-Type (%r) for JSON Error',
                        response_ct)
                try:
                    raise messages.Error.from_json(jobj)
                except jose.DeserializationError as error:
                    # Couldn't deserialize JSON object
                    raise errors.ClientError((response, error))
            else:
                # response is not JSON object
                raise errors.ClientError(response)
        else:
            if jobj is not None and response_ct != cls.JSON_CONTENT_TYPE:
                logger.debug(
                    'Ignoring wrong Content-Type (%r) for JSON decodable '
                    'response', response_ct)

            if content_type == cls.JSON_CONTENT_TYPE and jobj is None:
                raise errors.ClientError(
                    'Unexpected response Content-Type: {0}'.format(response_ct))

        return response

    def _send_request(self, method, url, *args, **kwargs):
        """Send HTTP request.

        Makes sure that `verify_ssl` is respected. Logs request and
        response (with headers). For allowed parameters please see
        `requests.request`.

        :param str method: method for the new `requests.Request` object
        :param str url: URL for the new `requests.Request` object

        :raises requests.exceptions.RequestException: in case of any problems

        :returns: HTTP Response
        :rtype: `requests.Response`


        """
        if method == "POST":
            logger.debug('Sending POST request to %s:\n%s',
                          url, kwargs['data'])
        else:
            logger.debug('Sending %s request to %s.', method, url)
        kwargs['verify'] = self.verify_ssl
        kwargs.setdefault('headers', {})
        kwargs['headers'].setdefault('User-Agent', self.user_agent)
        kwargs.setdefault('timeout', self._default_timeout)
        response = self.session.request(method, url, *args, **kwargs)
        # If content is DER, log the base64 of it instead of raw bytes, to keep
        # binary data out of the logs.
        if response.headers.get("Content-Type") == DER_CONTENT_TYPE:
            debug_content = base64.b64encode(response.content)
        else:
            debug_content = response.content
        logger.debug('Received response:\nHTTP %d\n%s\n\n%s',
                     response.status_code,
                     "\n".join(["{0}: {1}".format(k, v)
                                for k, v in response.headers.items()]),
                     debug_content)
        return response

    def head(self, *args, **kwargs):
        """Send HEAD request without checking the response.

        Note, that `_check_response` is not called, as it is expected
        that status code other than successfully 2xx will be returned, or
        messages2.Error will be raised by the server.

        """
        return self._send_request('HEAD', *args, **kwargs)

    def get(self, url, content_type=JSON_CONTENT_TYPE, **kwargs):
        """Send GET request and check response."""
        return self._check_response(
            self._send_request('GET', url, **kwargs), content_type=content_type)

    def _add_nonce(self, response):
        if self.REPLAY_NONCE_HEADER in response.headers:
            nonce = response.headers[self.REPLAY_NONCE_HEADER]
            try:
                decoded_nonce = jws.Header._fields['nonce'].decode(nonce)
            except jose.DeserializationError as error:
                raise errors.BadNonce(nonce, error)
            logger.debug('Storing nonce: %s', nonce)
            self._nonces.add(decoded_nonce)
        else:
            raise errors.MissingNonce(response)

    def _get_nonce(self, url):
        if not self._nonces:
            logger.debug('Requesting fresh nonce')
            self._add_nonce(self.head(url))
        return self._nonces.pop()

    def post(self, *args, **kwargs):
        """POST object wrapped in `.JWS` and check response.

        If the server responded with a badNonce error, the request will
        be retried once.

        """
        try:
            return self._post_once(*args, **kwargs)
        except messages.Error as error:
            if error.code == 'badNonce':
                logger.debug('Retrying request after error:\n%s', error)
                return self._post_once(*args, **kwargs)
            else:
                raise

    def _post_once(self, url, obj, content_type=JOSE_CONTENT_TYPE, **kwargs):
        data = self._wrap_in_jws(obj, self._get_nonce(url))
        kwargs.setdefault('headers', {'Content-Type': content_type})
        response = self._send_request('POST', url, data=data, **kwargs)
        self._add_nonce(response)
        return self._check_response(response, content_type=content_type)
