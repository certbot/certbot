"""ACME client API."""
import base64
import datetime
from email.utils import parsedate_tz
import http.client as http_client
import logging
import math
import random
import time
from typing import Any
from typing import cast
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union

from cryptography import x509

import josepy as jose
import requests
from requests.adapters import HTTPAdapter
from requests.utils import parse_header_links

from acme import challenges
from acme import crypto_util
from acme import errors
from acme import jws
from acme import messages

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_TIMEOUT = 45


class ClientV2:
    """ACME client for a v2 API.

    :ivar messages.Directory directory:
    :ivar .ClientNetwork net: Client network.
    """

    def __init__(self, directory: messages.Directory, net: 'ClientNetwork') -> None:
        """Initialize.

        :param .messages.Directory directory: Directory Resource
        :param .ClientNetwork net: Client network.
        """
        self.directory = directory
        self.net = net

    def new_account(self, new_account: messages.NewRegistration) -> messages.RegistrationResource:
        """Register.

        :param .NewRegistration new_account:

        :raises .ConflictError: in case the account already exists

        :returns: Registration Resource.
        :rtype: `.RegistrationResource`
        """
        response = self._post(self.directory['newAccount'], new_account)
        # if account already exists
        if response.status_code == 200 and 'Location' in response.headers:
            raise errors.ConflictError(response.headers['Location'])
        # "Instance of 'Field' has no key/contact member" bug:
        regr = self._regr_from_response(response)
        self.net.account = regr
        return regr

    def query_registration(self, regr: messages.RegistrationResource
                           ) -> messages.RegistrationResource:
        """Query server about registration.

        :param messages.RegistrationResource regr: Existing Registration
            Resource.

        """
        self.net.account = self._get_v2_account(regr, True)

        return self.net.account

    def update_registration(self, regr: messages.RegistrationResource,
                            update: Optional[messages.Registration] = None
                            ) -> messages.RegistrationResource:
        """Update registration.

        :param messages.RegistrationResource regr: Registration Resource.
        :param messages.Registration update: Updated body of the
            resource. If not provided, body will be taken from `regr`.

        :returns: Updated Registration Resource.
        :rtype: `.RegistrationResource`

        """
        # https://github.com/certbot/certbot/issues/6155
        regr = self._get_v2_account(regr)

        update = regr.body if update is None else update
        body = messages.UpdateRegistration(**dict(update))
        updated_regr = self._send_recv_regr(regr, body=body)
        self.net.account = updated_regr
        return updated_regr

    def _get_v2_account(self, regr: messages.RegistrationResource, update_body: bool = False
                       ) -> messages.RegistrationResource:
        self.net.account = None
        only_existing_reg = regr.body.update(only_return_existing=True)
        response = self._post(self.directory['newAccount'], only_existing_reg)
        updated_uri = response.headers['Location']
        new_regr = regr.update(body=messages.Registration.from_json(response.json())
                               if update_body else regr.body,
                               uri=updated_uri)
        self.net.account = new_regr
        return new_regr

    def new_order(self, csr_pem: bytes, profile: Optional[str] = None) -> messages.OrderResource:
        """Request a new Order object from the server.

        :param bytes csr_pem: A CSR in PEM format.

        :returns: The newly created order.
        :rtype: OrderResource
        """
        csr = x509.load_pem_x509_csr(csr_pem)
        dnsNames = crypto_util.get_names_from_subject_and_extensions(csr.subject, csr.extensions)
        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            ipNames = []
        else:
            ipNames = san_ext.value.get_values_for_type(x509.IPAddress)
        identifiers = []
        for name in dnsNames:
            identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_FQDN,
                value=name))
        for ip in ipNames:
            identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_IP,
                value=str(ip)))
        if profile is None:
            profile = ""
        order = messages.NewOrder(identifiers=identifiers, profile=profile)
        response = self._post(self.directory['newOrder'], order)
        body = messages.Order.from_json(response.json())
        authorizations = []
        # pylint has trouble understanding our josepy based objects which use
        # things like custom metaclass logic. body.authorizations should be a
        # list of strings containing URLs so let's disable this check here.
        for url in body.authorizations:  # pylint: disable=not-an-iterable
            authorizations.append(self._authzr_from_response(self._post_as_get(url), uri=url))
        return messages.OrderResource(
            body=body,
            uri=response.headers.get('Location'),
            authorizations=authorizations,
            csr_pem=csr_pem)

    def poll(self, authzr: messages.AuthorizationResource
             ) -> Tuple[messages.AuthorizationResource, requests.Response]:
        """Poll Authorization Resource for status.

        :param authzr: Authorization Resource
        :type authzr: `.AuthorizationResource`

        :returns: Updated Authorization Resource and HTTP response.

        :rtype: (`.AuthorizationResource`, `requests.Response`)

        """
        response = self._post_as_get(authzr.uri)
        updated_authzr = self._authzr_from_response(
            response, authzr.body.identifier, authzr.uri)
        return updated_authzr, response

    def poll_and_finalize(self, orderr: messages.OrderResource,
                          deadline: Optional[datetime.datetime] = None) -> messages.OrderResource:
        """Poll authorizations and finalize the order.

        If no deadline is provided, this method will timeout after 90
        seconds.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout

        :returns: finalized order
        :rtype: messages.OrderResource

        """
        if deadline is None:
            deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
        orderr = self.poll_authorizations(orderr, deadline)
        return self.finalize_order(orderr, deadline)

    def poll_authorizations(self, orderr: messages.OrderResource, deadline: datetime.datetime
                            ) -> messages.OrderResource:
        """Poll Order Resource for status."""
        responses = []
        for url in orderr.body.authorizations:
            while datetime.datetime.now() < deadline:
                authzr = self._authzr_from_response(self._post_as_get(url), uri=url)
                if authzr.body.status != messages.STATUS_PENDING:  # pylint: disable=no-member
                    responses.append(authzr)
                    break
                time.sleep(1)
        # If we didn't get a response for every authorization, we fell through
        # the bottom of the loop due to hitting the deadline.
        if len(responses) < len(orderr.body.authorizations):
            raise errors.TimeoutError()
        failed = []
        for authzr in responses:
            if authzr.body.status != messages.STATUS_VALID:
                for chall in authzr.body.challenges:
                    if chall.error is not None:
                        failed.append(authzr)
        if failed:
            raise errors.ValidationError(failed)
        return orderr.update(authorizations=responses)

    def begin_finalization(self, orderr: messages.OrderResource
                           ) -> messages.OrderResource:
        """Start the process of finalizing an order.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout

        :returns: updated order
        :rtype: messages.OrderResource

        :raises .messages.Error: If server indicates order is not yet in ready state,
            it will return a 403 (Forbidden) error with a problem document/error code of type
            "orderNotReady"

        """
        csr = x509.load_pem_x509_csr(orderr.csr_pem)
        wrapped_csr = messages.CertificateRequest(csr=csr)
        res = self._post(orderr.body.finalize, wrapped_csr)
        orderr = orderr.update(body=messages.Order.from_json(res.json()))
        return orderr

    def poll_finalization(self, orderr: messages.OrderResource,
                          deadline: datetime.datetime,
                          fetch_alternative_chains: bool = False
                          ) -> messages.OrderResource:
        """
        Poll an order that has been finalized for its status.
        If it becomes valid, obtain the certificate.

        If a finalization request previously returned `orderNotReady`,
        poll until ready, send a new finalization request, and continue
        polling until valid as above.

        :returns: finalized order (with certificate)
        :rtype: messages.OrderResource
        """
        sleep_seconds: float = 1
        while datetime.datetime.now() < deadline:
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
            response = self._post_as_get(orderr.uri)
            body = messages.Order.from_json(response.json())
            if body.status == messages.STATUS_INVALID:
                # "invalid": The certificate will not be issued.  Consider this
                # order process abandoned.
                if body.error is not None:
                    raise errors.IssuanceError(body.error)
                raise errors.Error(
                    "The certificate order failed. No further information was provided "
                    "by the server.")
            elif body.status == messages.STATUS_READY:
                # "ready": The server agrees that the requirements have been
                # fulfilled, and is awaiting finalization.  Submit a finalization
                # request.
                self.begin_finalization(orderr)
                sleep_seconds = 1
            elif body.status == messages.STATUS_VALID and body.certificate is not None:
                # "valid": The server has issued the certificate and provisioned its
                # URL to the "certificate" field of the order.  Download the
                # certificate.
                certificate_response = self._post_as_get(body.certificate)
                orderr = orderr.update(body=body, fullchain_pem=certificate_response.text)
                if fetch_alternative_chains:
                    alt_chains_urls = self._get_links(certificate_response, 'alternate')
                    alt_chains = [self._post_as_get(url).text for url in alt_chains_urls]
                    orderr = orderr.update(alternative_fullchains_pem=alt_chains)
                return orderr
            elif body.status == messages.STATUS_PROCESSING:
                # "processing": The certificate is being issued.  Send a POST-as-GET request after
                # the time given in the Retry-After header field of the response, if any.
                retry_after = self.retry_after(response, 1)
                # Whatever Retry-After the ACME server requests, the polling must not take
                # longer than the overall deadline
                retry_after = min(retry_after, deadline)
                sleep_seconds = (retry_after - datetime.datetime.now()).total_seconds()
        raise errors.TimeoutError()

    def finalize_order(self, orderr: messages.OrderResource, deadline: datetime.datetime,
                       fetch_alternative_chains: bool = False) -> messages.OrderResource:
        """Finalize an order and obtain a certificate.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout
        :param bool fetch_alternative_chains: whether to also fetch alternative
            certificate chains

        :returns: finalized order
        :rtype: messages.OrderResource

        """
        try:
            self.begin_finalization(orderr)
        except messages.Error as e:
            if e.code != 'orderNotReady':
                raise e
        return self.poll_finalization(orderr, deadline, fetch_alternative_chains)

    def renewal_time(self, cert_pem: bytes
        ) -> Tuple[Optional[datetime.datetime], datetime.datetime]:
        """Return an appropriate time to attempt renewal of the certificate,
        and the next time to ask the ACME server for renewal info.

        If the certificate has already expired, renewal info isn't checked.
        Instead, the certificate's notAfter time is returned and the certificate
        should be immediately renewed.

        If the ACME directory has a "renewalInfo" field, the response will be
        based on a fetch of the renewal info resource for the certificate
        (https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html).

        If there is no "renewalInfo" field, this function will return a tuple of
        None, and the next time to ask the ACME server for renewal info.

        This function may make other network calls in the future (e.g., OCSP
        or CRL).

        :param bytes cert_pem: cert as pem file

        :returns: Tuple of time to attempt renewal, next time to ask for renewal info
        """
        now = datetime.datetime.now()
        # https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html#section-4.3.3
        default_retry_after = datetime.timedelta(seconds=6 * 60 * 60)

        cert = x509.load_pem_x509_certificate(cert_pem)

        # from https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html#section-4.3, "Clients
        # MUST NOT check a certificate's RenewalInfo after the certificate has expired."
        #
        # we call datetime.datetime.now here with the UTC argument to create a timezone aware
        # datetime object that can be compared with the UTC notAfter from cryptography
        if cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
            return cert.not_valid_after_utc, now + default_retry_after

        try:
            renewal_info_base_url = self.directory['renewalInfo']
        except KeyError:
            return None, now + default_retry_after

        ari_url = renewal_info_base_url + '/' + _renewal_info_path_component(cert)
        try:
            resp = self.net.get(ari_url, content_type='application/json')
        except (requests.exceptions.RequestException, messages.Error) as error:
            logger.info("failed to fetch renewal_info URL (%s): %s", ari_url, error)
            return None, now + default_retry_after

        renewal_info: messages.RenewalInfo = messages.RenewalInfo.from_json(resp.json())

        start = renewal_info.suggested_window.start # pylint: disable=no-member
        end = renewal_info.suggested_window.end # pylint: disable=no-member

        delta_seconds = (end - start).total_seconds()
        random_seconds = random.uniform(0, delta_seconds)
        random_time = start + datetime.timedelta(seconds=random_seconds)

        retry_after = self.retry_after(resp, default_retry_after.seconds)
        return random_time, retry_after


    def revoke(self, cert: x509.Certificate, rsn: int) -> None:
        """Revoke certificate.

        :param x509.Certificate cert: `x509.Certificate`

        :param int rsn: Reason code for certificate revocation.

        :raises .ClientError: If revocation is unsuccessful.

        """
        self._revoke(cert, rsn, self.directory['revokeCert'])

    def external_account_required(self) -> bool:
        """Checks if ACME server requires External Account Binding authentication."""
        return hasattr(self.directory, 'meta') and \
               hasattr(self.directory.meta, 'external_account_required') and \
               self.directory.meta.external_account_required

    def _post_as_get(self, *args: Any, **kwargs: Any) -> requests.Response:
        """
        Send GET request using the POST-as-GET protocol.
        :param args:
        :param kwargs:
        :return:
        """
        new_args = args[:1] + (None,) + args[1:]
        return self._post(*new_args, **kwargs)

    def _get_links(self, response: requests.Response, relation_type: str) -> List[str]:
        """
        Retrieves all Link URIs of relation_type from the response.
        :param requests.Response response: The requests HTTP response.
        :param str relation_type: The relation type to filter by.
        """
        # Can't use response.links directly because it drops multiple links
        # of the same relation type, which is possible in RFC8555 responses.
        if 'Link' not in response.headers:
            return []
        links = parse_header_links(response.headers['Link'])
        return [l['url'] for l in links
                if 'rel' in l and 'url' in l and l['rel'] == relation_type]

    @classmethod
    def get_directory(cls, url: str, net: 'ClientNetwork') -> messages.Directory:
        """
        Retrieves the ACME directory (RFC 8555 section 7.1.1) from the ACME server.
        :param str url: the URL where the ACME directory is available
        :param ClientNetwork net: the ClientNetwork to use to make the request

        :returns: the ACME directory object
        :rtype: messages.Directory
        """
        return messages.Directory.from_json(net.get(url).json())

    @classmethod
    def _regr_from_response(cls, response: requests.Response, uri: Optional[str] = None,
                            terms_of_service: Optional[str] = None
                            ) -> messages.RegistrationResource:
        if 'terms-of-service' in response.links:
            terms_of_service = response.links['terms-of-service']['url']

        return messages.RegistrationResource(
            body=messages.Registration.from_json(response.json()),
            uri=response.headers.get('Location', uri),
            terms_of_service=terms_of_service)

    def _send_recv_regr(self, regr: messages.RegistrationResource,
                        body: messages.Registration) -> messages.RegistrationResource:
        response = self._post(regr.uri, body)

        # TODO: Boulder returns httplib.ACCEPTED
        #assert response.status_code == httplib.OK

        # TODO: Boulder does not set Location or Link on update
        # (c.f. acme-spec #94)

        return self._regr_from_response(
            response, uri=regr.uri,
            terms_of_service=regr.terms_of_service)

    def _post(self, *args: Any, **kwargs: Any) -> requests.Response:
        """Wrapper around self.net.post that adds the newNonce URL.

        This is used to retry the request in case of a badNonce error.

        """
        kwargs.setdefault('new_nonce_url', getattr(self.directory, 'newNonce'))
        return self.net.post(*args, **kwargs)

    def deactivate_registration(self, regr: messages.RegistrationResource
                                ) -> messages.RegistrationResource:
        """Deactivate registration.

        :param messages.RegistrationResource regr: The Registration Resource
            to be deactivated.

        :returns: The Registration resource that was deactivated.
        :rtype: `.RegistrationResource`

        """
        return self.update_registration(regr, messages.Registration.from_json(
            {"status": "deactivated", "contact": None}))

    def deactivate_authorization(self,
                                 authzr: messages.AuthorizationResource
                                 ) -> messages.AuthorizationResource:
        """Deactivate authorization.

        :param messages.AuthorizationResource authzr: The Authorization resource
            to be deactivated.

        :returns: The Authorization resource that was deactivated.
        :rtype: `.AuthorizationResource`

        """
        body = messages.UpdateAuthorization(status='deactivated')
        response = self._post(authzr.uri, body)
        return self._authzr_from_response(response,
            authzr.body.identifier, authzr.uri)

    def _authzr_from_response(self, response: requests.Response,
                              identifier: Optional[messages.Identifier] = None,
                              uri: Optional[str] = None) -> messages.AuthorizationResource:
        authzr = messages.AuthorizationResource(
            body=messages.Authorization.from_json(response.json()),
            uri=response.headers.get('Location', uri))
        if identifier is not None and authzr.body.identifier != identifier:  # pylint: disable=no-member
            raise errors.UnexpectedUpdate(authzr)
        return authzr

    def answer_challenge(self, challb: messages.ChallengeBody,
                         response: challenges.ChallengeResponse) -> messages.ChallengeResource:
        """Answer challenge.

        :param challb: Challenge Resource body.
        :type challb: `.ChallengeBody`

        :param response: Corresponding Challenge response
        :type response: `.challenges.ChallengeResponse`

        :returns: Challenge Resource with updated body.
        :rtype: `.ChallengeResource`

        :raises .UnexpectedUpdate:

        """
        resp = self._post(challb.uri, response)
        try:
            authzr_uri = resp.links['up']['url']
        except KeyError:
            raise errors.ClientError('"up" Link header missing')
        challr = messages.ChallengeResource(
            authzr_uri=authzr_uri,
            body=messages.ChallengeBody.from_json(resp.json()))
        # TODO: check that challr.uri == resp.headers['Location']?
        if challr.uri != challb.uri:
            raise errors.UnexpectedUpdate(challr.uri)
        return challr

    @classmethod
    def retry_after(cls, response: requests.Response, default: int) -> datetime.datetime:
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
                    tz_secs = datetime.timedelta(when[-1] if when[-1] is not None else 0)
                    return datetime.datetime(*when[:7]) - tz_secs
                except (ValueError, OverflowError):
                    pass
            seconds = default

        return datetime.datetime.now() + datetime.timedelta(seconds=seconds)

    def _revoke(self, cert: x509.Certificate, rsn: int, url: str) -> None:
        """Revoke certificate.

        :param .x509.Certificate cert: `x509.Certificate`

        :param int rsn: Reason code for certificate revocation.

        :param str url: ACME URL to post to

        :raises .ClientError: If revocation is unsuccessful.

        """
        response = self._post(url,
                              messages.Revocation(
                                certificate=cert,
                                reason=rsn))
        if response.status_code != http_client.OK:
            raise errors.ClientError(
                'Successful revocation must return HTTP OK status')


class ClientNetwork:
    """Wrapper around requests that signs POSTs for authentication.

    Also adds user agent, and handles Content-Type.
    """
    JSON_CONTENT_TYPE = 'application/json'
    JOSE_CONTENT_TYPE = 'application/jose+json'
    JSON_ERROR_CONTENT_TYPE = 'application/problem+json'
    REPLAY_NONCE_HEADER = 'Replay-Nonce'

    """Initialize.

    :param josepy.JWK key: Account private key. Required to use .post().
    :param messages.RegistrationResource account: Account object. Required if you are
            planning to use .post() for anything other than creating a new account;
            may be set later after registering.
    :param josepy.JWASignature alg: Algorithm to use in signing JWS.
    :param bool verify_ssl: Whether to verify certificates on SSL connections.
    :param str user_agent: String to send as User-Agent header.
    :param int timeout: Timeout for requests.
    """
    def __init__(self, key: Optional[jose.JWK] = None,
                 account: Optional[messages.RegistrationResource] = None,
                 alg: jose.JWASignature = jose.RS256, verify_ssl: bool = True,
                 user_agent: str = 'acme-python', timeout: int = DEFAULT_NETWORK_TIMEOUT) -> None:
        self.key = key
        self.account = account
        self.alg = alg
        self.verify_ssl = verify_ssl
        self._nonces: Set[str] = set()
        self.user_agent = user_agent
        self.session = requests.Session()
        self._default_timeout = timeout
        adapter = HTTPAdapter()

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def __del__(self) -> None:
        # Try to close the session, but don't show exceptions to the
        # user if the call to close() fails. See #4840.
        try:
            self.session.close()
        except Exception:  # pylint: disable=broad-except
            pass

    def _wrap_in_jws(self, obj: jose.JSONDeSerializable, nonce: str, url: str) -> str:
        """Wrap `JSONDeSerializable` object in JWS.

        .. todo:: Implement ``acmePath``.

        :param josepy.JSONDeSerializable obj:
        :param str url: The URL to which this object will be POSTed
        :param str nonce:
        :rtype: str

        """
        jobj = obj.json_dumps(indent=2).encode() if obj else b''
        logger.debug('JWS payload:\n%s', jobj)
        assert self.key
        kwargs = {
            "alg": self.alg,
            "nonce": nonce,
            "url": url,
            "key": self.key
        }
        # newAccount and revokeCert work without the kid
        # newAccount must not have kid
        if self.account is not None:
            kwargs["kid"] = self.account["uri"]
        return jws.JWS.sign(jobj, **cast(Mapping[str, Any], kwargs)).json_dumps(indent=2)

    @classmethod
    def _check_response(cls, response: requests.Response,
                        content_type: Optional[str] = None) -> requests.Response:
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
            carries HTTP Problem (https://datatracker.ietf.org/doc/html/rfc7807).
        :raises .ClientError: In case of other networking errors.

        """
        response_ct = response.headers.get('Content-Type')
        # Strip parameters from the media-type (rfc2616#section-3.7)
        if response_ct:
            response_ct = response_ct.split(';')[0].strip()
        try:
            # TODO: response.json() is called twice, once here, and
            # once in _get and _post clients
            jobj = response.json()
        except ValueError:
            jobj = None

        if response.status_code == 409:
            raise errors.ConflictError(response.headers.get('Location', 'UNKNOWN-LOCATION'))

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
                raise errors.ClientError(f'Unexpected response Content-Type: {response_ct}')

        return response

    def _send_request(self, method: str, url: str, *args: Any, **kwargs: Any) -> requests.Response:
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

        # If an Accept header was sent in the request, the response may not be
        # UTF-8 encoded. In this case, we don't set response.encoding and log
        # the base64 response instead of raw bytes to keep binary data out of the logs.
        debug_content: Union[bytes, str]
        if "Accept" in kwargs["headers"]:
            debug_content = base64.b64encode(response.content)
        else:
            # We set response.encoding so response.text knows the response is
            # UTF-8 encoded instead of trying to guess the encoding that was
            # used which is error prone. This setting affects all future
            # accesses of .text made on the returned response object as well.
            response.encoding = "utf-8"
            debug_content = response.text
        logger.debug('Received response:\nHTTP %d\n%s\n\n%s',
                     response.status_code,
                     "\n".join("{0}: {1}".format(k, v)
                                for k, v in response.headers.items()),
                     debug_content)
        return response

    def head(self, *args: Any, **kwargs: Any) -> requests.Response:
        """Send HEAD request without checking the response.

        Note, that `_check_response` is not called, as it is expected
        that status code other than successfully 2xx will be returned, or
        messages2.Error will be raised by the server.

        """
        return self._send_request('HEAD', *args, **kwargs)

    def get(self, url: str, content_type: str = JSON_CONTENT_TYPE,
            **kwargs: Any) -> requests.Response:
        """Send GET request and check response."""
        return self._check_response(
            self._send_request('GET', url, **kwargs), content_type=content_type)

    def _add_nonce(self, response: requests.Response) -> None:
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

    def _get_nonce(self, url: str, new_nonce_url: str) -> str:
        if not self._nonces:
            logger.debug('Requesting fresh nonce')
            if new_nonce_url is None:
                response = self.head(url)
            else:
                # request a new nonce from the acme newNonce endpoint
                response = self._check_response(self.head(new_nonce_url), content_type=None)
            self._add_nonce(response)
        return self._nonces.pop()

    def post(self, *args: Any, **kwargs: Any) -> requests.Response:
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
            raise

    def _post_once(self, url: str, obj: jose.JSONDeSerializable,
                   content_type: str = JOSE_CONTENT_TYPE, **kwargs: Any) -> requests.Response:
        new_nonce_url = kwargs.pop('new_nonce_url', None)
        if not self.key:
            raise errors.Error("acme.ClientNetwork with no private key can't POST.")
        data = self._wrap_in_jws(obj, self._get_nonce(url, new_nonce_url), url)
        kwargs.setdefault('headers', {'Content-Type': content_type})
        response = self._send_request('POST', url, data=data, **kwargs)
        response = self._check_response(response, content_type=content_type)
        self._add_nonce(response)
        return response

def _renewal_info_path_component(cert: x509.Certificate) -> str:
    akid_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    key_identifier = akid_ext.value.key_identifier # type: ignore[attr-defined]

    akid_encoded = base64.urlsafe_b64encode(key_identifier).decode('ascii').replace("=", "")

    # We add one to the reported bit_length so there is room for the sign bit.
    # https://docs.python.org/3/library/stdtypes.html#int.bit_length
    # "Return the number of bits necessary to represent an integer in binary, excluding
    # the sign and leading zeros"
    serial = cert.serial_number
    encoded_serial_len = math.ceil((serial.bit_length()+1)/8)
    # Serials are encoded as ASN.1 INTEGERS, which means big endian and signed (two's complement).
    # https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#integer-encoding
    serial_bytes = serial.to_bytes(encoded_serial_len, byteorder='big', signed=True)
    serial_encoded = base64.urlsafe_b64encode(serial_bytes).decode('ascii').replace("=", "")

    return f"{akid_encoded}.{serial_encoded}"
