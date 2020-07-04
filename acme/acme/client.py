"""ACME client API."""
import base64
import collections
import datetime
from email.utils import parsedate_tz
import heapq
import logging
import re
import sys
import time

import josepy as jose
import OpenSSL
import requests
from requests.adapters import HTTPAdapter
from requests.utils import parse_header_links
from requests_toolbelt.adapters.source import SourceAddressAdapter
import six
from six.moves import http_client

from acme import crypto_util
from acme import errors
from acme import jws
from acme import messages
from acme.magic_typing import Dict
from acme.magic_typing import List
from acme.magic_typing import Set
from acme.magic_typing import Text
from acme.mixins import VersionedLEACMEMixin

logger = logging.getLogger(__name__)

# Prior to Python 2.7.9 the stdlib SSL module did not allow a user to configure
# many important security related options. On these platforms we use PyOpenSSL
# for SSL, which does allow these options to be configured.
# https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
if sys.version_info < (2, 7, 9):  # pragma: no cover
    try:
        requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()  # type: ignore
    except AttributeError:
        import urllib3.contrib.pyopenssl
        urllib3.contrib.pyopenssl.inject_into_urllib3()

DEFAULT_NETWORK_TIMEOUT = 45

DER_CONTENT_TYPE = 'application/pkix-cert'


class ClientBase(object):
    """ACME client base object.

    :ivar messages.Directory directory:
    :ivar .ClientNetwork net: Client network.
    :ivar int acme_version: ACME protocol version. 1 or 2.
    """
    def __init__(self, directory, net, acme_version):
        """Initialize.

        :param .messages.Directory directory: Directory Resource
        :param .ClientNetwork net: Client network.
        :param int acme_version: ACME protocol version. 1 or 2.
        """
        self.directory = directory
        self.net = net
        self.acme_version = acme_version

    @classmethod
    def _regr_from_response(cls, response, uri=None, terms_of_service=None):
        if 'terms-of-service' in response.links:
            terms_of_service = response.links['terms-of-service']['url']

        return messages.RegistrationResource(
            body=messages.Registration.from_json(response.json()),
            uri=response.headers.get('Location', uri),
            terms_of_service=terms_of_service)

    def _send_recv_regr(self, regr, body):
        response = self._post(regr.uri, body)

        # TODO: Boulder returns httplib.ACCEPTED
        #assert response.status_code == httplib.OK

        # TODO: Boulder does not set Location or Link on update
        # (c.f. acme-spec #94)

        return self._regr_from_response(
            response, uri=regr.uri,
            terms_of_service=regr.terms_of_service)

    def _post(self, *args, **kwargs):
        """Wrapper around self.net.post that adds the acme_version.

        """
        kwargs.setdefault('acme_version', self.acme_version)
        if hasattr(self.directory, 'newNonce'):
            kwargs.setdefault('new_nonce_url', getattr(self.directory, 'newNonce'))
        return self.net.post(*args, **kwargs)

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
        self.net.account = updated_regr
        return updated_regr

    def deactivate_registration(self, regr):
        """Deactivate registration.

        :param messages.RegistrationResource regr: The Registration Resource
            to be deactivated.

        :returns: The Registration resource that was deactivated.
        :rtype: `.RegistrationResource`

        """
        return self.update_registration(regr, update={'status': 'deactivated'})

    def deactivate_authorization(self, authzr):
        # type: (messages.AuthorizationResource) -> messages.AuthorizationResource
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

    def _authzr_from_response(self, response, identifier=None, uri=None):
        authzr = messages.AuthorizationResource(
            body=messages.Authorization.from_json(response.json()),
            uri=response.headers.get('Location', uri))
        if identifier is not None and authzr.body.identifier != identifier:
            raise errors.UnexpectedUpdate(authzr)
        return authzr

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
        response = self._post(challb.uri, response)
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

    def _revoke(self, cert, rsn, url):
        """Revoke certificate.

        :param .ComparableX509 cert: `OpenSSL.crypto.X509` wrapped in
            `.ComparableX509`

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


class Client(ClientBase):
    """ACME client for a v1 API.

    .. todo::
       Clean up raised error types hierarchy, document, and handle (wrap)
       instances of `.DeserializationError` raised in `from_json()`.

    :ivar messages.Directory directory:
    :ivar key: `josepy.JWK` (private)
    :ivar alg: `josepy.JWASignature`
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
        if net is None:
            net = ClientNetwork(key, alg=alg, verify_ssl=verify_ssl)

        if isinstance(directory, six.string_types):
            directory = messages.Directory.from_json(
                net.get(directory).json())
        super(Client, self).__init__(directory=directory,
            net=net, acme_version=1)

    def register(self, new_reg=None):
        """Register.

        :param .NewRegistration new_reg:

        :returns: Registration Resource.
        :rtype: `.RegistrationResource`

        """
        new_reg = messages.NewRegistration() if new_reg is None else new_reg
        response = self._post(self.directory[new_reg], new_reg)
        # TODO: handle errors
        assert response.status_code == http_client.CREATED

        # "Instance of 'Field' has no key/contact member" bug:
        return self._regr_from_response(response)

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

    def request_challenges(self, identifier, new_authzr_uri=None):
        """Request challenges.

        :param .messages.Identifier identifier: Identifier to be challenged.
        :param str new_authzr_uri: Deprecated. Do not use.

        :returns: Authorization Resource.
        :rtype: `.AuthorizationResource`

        :raises errors.WildcardUnsupportedError: if a wildcard is requested

        """
        if new_authzr_uri is not None:
            logger.debug("request_challenges with new_authzr_uri deprecated.")

        if identifier.value.startswith("*"):
            raise errors.WildcardUnsupportedError(
                "Requesting an authorization for a wildcard name is"
                " forbidden by this version of the ACME protocol.")

        new_authz = messages.NewAuthorization(identifier=identifier)
        response = self._post(self.directory.new_authz, new_authz)
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

        :raises errors.WildcardUnsupportedError: if a wildcard is requested

        """
        return self.request_challenges(messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value=domain), new_authzr_uri)

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
        response = self._post(
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
        assert max_attempts > 0
        attempts = collections.defaultdict(int) # type: Dict[messages.AuthorizationResource, int]
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
            (response, :class:`josepy.util.ComparableX509`)
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
        chain = [] # type: List[jose.ComparableX509]
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
        return self._revoke(cert, rsn, self.directory[messages.Revocation])


class ClientV2(ClientBase):
    """ACME client for a v2 API.

    :ivar messages.Directory directory:
    :ivar .ClientNetwork net: Client network.
    """

    def __init__(self, directory, net):
        """Initialize.

        :param .messages.Directory directory: Directory Resource
        :param .ClientNetwork net: Client network.
        """
        super(ClientV2, self).__init__(directory=directory,
            net=net, acme_version=2)

    def new_account(self, new_account):
        """Register.

        :param .NewRegistration new_account:

        :raises .ConflictError: in case the account already exists

        :returns: Registration Resource.
        :rtype: `.RegistrationResource`
        """
        response = self._post(self.directory['newAccount'], new_account)
        # if account already exists
        if response.status_code == 200 and 'Location' in response.headers:
            raise errors.ConflictError(response.headers.get('Location'))
        # "Instance of 'Field' has no key/contact member" bug:
        regr = self._regr_from_response(response)
        self.net.account = regr
        return regr

    def query_registration(self, regr):
        """Query server about registration.

        :param messages.RegistrationResource: Existing Registration
            Resource.

        """
        self.net.account = regr  # See certbot/certbot#6258
        # ACME v2 requires to use a POST-as-GET request (POST an empty JWS) here.
        # This is done by passing None instead of an empty UpdateRegistration to _post().
        response = self._post(regr.uri, None)
        self.net.account = self._regr_from_response(response, uri=regr.uri,
                                                    terms_of_service=regr.terms_of_service)
        return self.net.account

    def update_registration(self, regr, update=None):
        """Update registration.

        :param messages.RegistrationResource regr: Registration Resource.
        :param messages.Registration update: Updated body of the
            resource. If not provided, body will be taken from `regr`.

        :returns: Updated Registration Resource.
        :rtype: `.RegistrationResource`

        """
        # https://github.com/certbot/certbot/issues/6155
        new_regr = self._get_v2_account(regr)
        return super(ClientV2, self).update_registration(new_regr, update)

    def _get_v2_account(self, regr):
        self.net.account = None
        only_existing_reg = regr.body.update(only_return_existing=True)
        response = self._post(self.directory['newAccount'], only_existing_reg)
        updated_uri = response.headers['Location']
        new_regr = regr.update(uri=updated_uri)
        self.net.account = new_regr
        return new_regr

    def new_order(self, csr_pem):
        """Request a new Order object from the server.

        :param str csr_pem: A CSR in PEM format.

        :returns: The newly created order.
        :rtype: OrderResource
        """
        csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)
        # pylint: disable=protected-access
        dnsNames = crypto_util._pyopenssl_cert_or_req_all_names(csr)

        identifiers = []
        for name in dnsNames:
            identifiers.append(messages.Identifier(typ=messages.IDENTIFIER_FQDN,
                value=name))
        order = messages.NewOrder(identifiers=identifiers)
        response = self._post(self.directory['newOrder'], order)
        body = messages.Order.from_json(response.json())
        authorizations = []
        for url in body.authorizations:
            authorizations.append(self._authzr_from_response(self._post_as_get(url), uri=url))
        return messages.OrderResource(
            body=body,
            uri=response.headers.get('Location'),
            authorizations=authorizations,
            csr_pem=csr_pem)

    def poll(self, authzr):
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

    def poll_and_finalize(self, orderr, deadline=None):
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

    def poll_authorizations(self, orderr, deadline):
        """Poll Order Resource for status."""
        responses = []
        for url in orderr.body.authorizations:
            while datetime.datetime.now() < deadline:
                authzr = self._authzr_from_response(self._post_as_get(url), uri=url)
                if authzr.body.status != messages.STATUS_PENDING:
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

    def finalize_order(self, orderr, deadline, fetch_alternative_chains=False):
        """Finalize an order and obtain a certificate.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout
        :param bool fetch_alternative_chains: whether to also fetch alternative
            certificate chains

        :returns: finalized order
        :rtype: messages.OrderResource

        """
        csr = OpenSSL.crypto.load_certificate_request(
            OpenSSL.crypto.FILETYPE_PEM, orderr.csr_pem)
        wrapped_csr = messages.CertificateRequest(csr=jose.ComparableX509(csr))
        self._post(orderr.body.finalize, wrapped_csr)
        while datetime.datetime.now() < deadline:
            time.sleep(1)
            response = self._post_as_get(orderr.uri)
            body = messages.Order.from_json(response.json())
            if body.error is not None:
                raise errors.IssuanceError(body.error)
            if body.certificate is not None:
                certificate_response = self._post_as_get(body.certificate)
                orderr = orderr.update(body=body, fullchain_pem=certificate_response.text)
                if fetch_alternative_chains:
                    alt_chains_urls = self._get_links(certificate_response, 'alternate')
                    alt_chains = [self._post_as_get(url).text for url in alt_chains_urls]
                    orderr = orderr.update(alternative_fullchains_pem=alt_chains)
                return orderr
        raise errors.TimeoutError()

    def revoke(self, cert, rsn):
        """Revoke certificate.

        :param .ComparableX509 cert: `OpenSSL.crypto.X509` wrapped in
            `.ComparableX509`

        :param int rsn: Reason code for certificate revocation.

        :raises .ClientError: If revocation is unsuccessful.

        """
        return self._revoke(cert, rsn, self.directory['revokeCert'])

    def external_account_required(self):
        """Checks if ACME server requires External Account Binding authentication."""
        return hasattr(self.directory, 'meta') and self.directory.meta.external_account_required

    def _post_as_get(self, *args, **kwargs):
        """
        Send GET request using the POST-as-GET protocol.
        :param args:
        :param kwargs:
        :return:
        """
        new_args = args[:1] + (None,) + args[1:]
        return self._post(*new_args, **kwargs)

    def _get_links(self, response, relation_type):
        """
        Retrieves all Link URIs of relation_type from the response.
        :param requests.Response response: The requests HTTP response.
        :param str relation_type: The relation type to filter by.
        """
        # Can't use response.links directly because it drops multiple links
        # of the same relation type, which is possible in RFC8555 responses.
        if not 'Link' in response.headers:
            return []
        links = parse_header_links(response.headers['Link'])
        return [l['url'] for l in links
                if 'rel' in l and 'url' in l and l['rel'] == relation_type]


class BackwardsCompatibleClientV2(object):
    """ACME client wrapper that tends towards V2-style calls, but
    supports V1 servers.

    .. note:: While this class handles the majority of the differences
        between versions of the ACME protocol, if you need to support an
        ACME server based on version 3 or older of the IETF ACME draft
        that uses combinations in authorizations (or lack thereof) to
        signal that the client needs to complete something other than
        any single challenge in the authorization to make it valid, the
        user of this class needs to understand and handle these
        differences themselves.  This does not apply to either of Let's
        Encrypt's endpoints where successfully completing any challenge
        in an authorization will make it valid.

    :ivar int acme_version: 1 or 2, corresponding to the Let's Encrypt endpoint
    :ivar .ClientBase client: either Client or ClientV2
    """

    def __init__(self, net, key, server):
        directory = messages.Directory.from_json(net.get(server).json())
        self.acme_version = self._acme_version_from_directory(directory)
        if self.acme_version == 1:
            self.client = Client(directory, key=key, net=net)
        else:
            self.client = ClientV2(directory, net=net)

    def __getattr__(self, name):
        return getattr(self.client, name)

    def new_account_and_tos(self, regr, check_tos_cb=None):
        """Combined register and agree_tos for V1, new_account for V2

        :param .NewRegistration regr:
        :param callable check_tos_cb: callback that raises an error if
            the check does not work
        """
        def _assess_tos(tos):
            if check_tos_cb is not None:
                check_tos_cb(tos)
        if self.acme_version == 1:
            regr = self.client.register(regr)
            if regr.terms_of_service is not None:
                _assess_tos(regr.terms_of_service)
                return self.client.agree_to_tos(regr)
            return regr
        else:
            if "terms_of_service" in self.client.directory.meta:
                _assess_tos(self.client.directory.meta.terms_of_service)
                regr = regr.update(terms_of_service_agreed=True)
            return self.client.new_account(regr)

    def new_order(self, csr_pem):
        """Request a new Order object from the server.

        If using ACMEv1, returns a dummy OrderResource with only
        the authorizations field filled in.

        :param str csr_pem: A CSR in PEM format.

        :returns: The newly created order.
        :rtype: OrderResource

        :raises errors.WildcardUnsupportedError: if a wildcard domain is
            requested but unsupported by the ACME version

        """
        if self.acme_version == 1:
            csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)
            # pylint: disable=protected-access
            dnsNames = crypto_util._pyopenssl_cert_or_req_all_names(csr)
            authorizations = []
            for domain in dnsNames:
                authorizations.append(self.client.request_domain_challenges(domain))
            return messages.OrderResource(authorizations=authorizations, csr_pem=csr_pem)
        return self.client.new_order(csr_pem)

    def finalize_order(self, orderr, deadline, fetch_alternative_chains=False):
        """Finalize an order and obtain a certificate.

        :param messages.OrderResource orderr: order to finalize
        :param datetime.datetime deadline: when to stop polling and timeout
        :param bool fetch_alternative_chains: whether to also fetch alternative
            certificate chains

        :returns: finalized order
        :rtype: messages.OrderResource

        """
        if self.acme_version == 1:
            csr_pem = orderr.csr_pem
            certr = self.client.request_issuance(
                jose.ComparableX509(
                    OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)),
                    orderr.authorizations)

            chain = None
            while datetime.datetime.now() < deadline:
                try:
                    chain = self.client.fetch_chain(certr)
                    break
                except errors.Error:
                    time.sleep(1)

            if chain is None:
                raise errors.TimeoutError(
                    'Failed to fetch chain. You should not deploy the generated '
                    'certificate, please rerun the command for a new one.')

            cert = OpenSSL.crypto.dump_certificate(
                    OpenSSL.crypto.FILETYPE_PEM, certr.body.wrapped).decode()
            chain = crypto_util.dump_pyopenssl_chain(chain).decode()

            return orderr.update(fullchain_pem=(cert + chain))
        return self.client.finalize_order(orderr, deadline, fetch_alternative_chains)

    def revoke(self, cert, rsn):
        """Revoke certificate.

        :param .ComparableX509 cert: `OpenSSL.crypto.X509` wrapped in
            `.ComparableX509`

        :param int rsn: Reason code for certificate revocation.

        :raises .ClientError: If revocation is unsuccessful.

        """
        return self.client.revoke(cert, rsn)

    def _acme_version_from_directory(self, directory):
        if hasattr(directory, 'newNonce'):
            return 2
        return 1

    def external_account_required(self):
        """Checks if the server requires an external account for ACMEv2 servers.

        Always return False for ACMEv1 servers, as it doesn't use External Account Binding."""
        if self.acme_version == 1:
            return False
        return self.client.external_account_required()


class ClientNetwork(object):
    """Wrapper around requests that signs POSTs for authentication.

    Also adds user agent, and handles Content-Type.
    """
    JSON_CONTENT_TYPE = 'application/json'
    JOSE_CONTENT_TYPE = 'application/jose+json'
    JSON_ERROR_CONTENT_TYPE = 'application/problem+json'
    REPLAY_NONCE_HEADER = 'Replay-Nonce'

    """Initialize.

    :param josepy.JWK key: Account private key
    :param messages.RegistrationResource account: Account object. Required if you are
            planning to use .post() with acme_version=2 for anything other than
            creating a new account; may be set later after registering.
    :param josepy.JWASignature alg: Algorithm to use in signing JWS.
    :param bool verify_ssl: Whether to verify certificates on SSL connections.
    :param str user_agent: String to send as User-Agent header.
    :param float timeout: Timeout for requests.
    :param source_address: Optional source address to bind to when making requests.
    :type source_address: str or tuple(str, int)
    """
    def __init__(self, key, account=None, alg=jose.RS256, verify_ssl=True,
                 user_agent='acme-python', timeout=DEFAULT_NETWORK_TIMEOUT,
                 source_address=None):
        self.key = key
        self.account = account
        self.alg = alg
        self.verify_ssl = verify_ssl
        self._nonces = set() # type: Set[Text]
        self.user_agent = user_agent
        self.session = requests.Session()
        self._default_timeout = timeout
        adapter = HTTPAdapter()

        if source_address is not None:
            adapter = SourceAddressAdapter(source_address)

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def __del__(self):
        # Try to close the session, but don't show exceptions to the
        # user if the call to close() fails. See #4840.
        try:
            self.session.close()
        except Exception:  # pylint: disable=broad-except
            pass

    def _wrap_in_jws(self, obj, nonce, url, acme_version):
        """Wrap `JSONDeSerializable` object in JWS.

        .. todo:: Implement ``acmePath``.

        :param josepy.JSONDeSerializable obj:
        :param str url: The URL to which this object will be POSTed
        :param bytes nonce:
        :rtype: `josepy.JWS`

        """
        if isinstance(obj, VersionedLEACMEMixin):
            obj.le_acme_version = acme_version
        jobj = obj.json_dumps(indent=2).encode() if obj else b''
        logger.debug('JWS payload:\n%s', jobj)
        kwargs = {
            "alg": self.alg,
            "nonce": nonce
        }
        if acme_version == 2:
            kwargs["url"] = url
            # newAccount and revokeCert work without the kid
            # newAccount must not have kid
            if self.account is not None:
                kwargs["kid"] = self.account["uri"]
        kwargs["key"] = self.key
        return jws.JWS.sign(jobj, **kwargs).json_dumps(indent=2)

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
            raise errors.ConflictError(response.headers.get('Location'))

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
        try:
            response = self.session.request(method, url, *args, **kwargs)
        except requests.exceptions.RequestException as e:
            # pylint: disable=pointless-string-statement
            """Requests response parsing

            The requests library emits exceptions with a lot of extra text.
            We parse them with a regexp to raise a more readable exceptions.

            Example:
            HTTPSConnectionPool(host='acme-v01.api.letsencrypt.org',
            port=443): Max retries exceeded with url: /directory
            (Caused by NewConnectionError('
            <requests.packages.urllib3.connection.VerifiedHTTPSConnection
            object at 0x108356c50>: Failed to establish a new connection:
            [Errno 65] No route to host',))"""

            # pylint: disable=line-too-long
            err_regex = r".*host='(\S*)'.*Max retries exceeded with url\: (\/\w*).*(\[Errno \d+\])([A-Za-z ]*)"
            m = re.match(err_regex, str(e))
            if m is None:
                raise  # pragma: no cover
            host, path, _err_no, err_msg = m.groups()
            raise ValueError("Requesting {0}{1}:{2}".format(host, path, err_msg))

        # If content is DER, log the base64 of it instead of raw bytes, to keep
        # binary data out of the logs.
        if response.headers.get("Content-Type") == DER_CONTENT_TYPE:
            debug_content = base64.b64encode(response.content)
        else:
            debug_content = response.content.decode("utf-8")
        logger.debug('Received response:\nHTTP %d\n%s\n\n%s',
                     response.status_code,
                     "\n".join("{0}: {1}".format(k, v)
                                for k, v in response.headers.items()),
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

    def _get_nonce(self, url, new_nonce_url):
        if not self._nonces:
            logger.debug('Requesting fresh nonce')
            if new_nonce_url is None:
                response = self.head(url)
            else:
                # request a new nonce from the acme newNonce endpoint
                response = self._check_response(self.head(new_nonce_url), content_type=None)
            self._add_nonce(response)
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
            raise

    def _post_once(self, url, obj, content_type=JOSE_CONTENT_TYPE,
            acme_version=1, **kwargs):
        new_nonce_url = kwargs.pop('new_nonce_url', None)
        data = self._wrap_in_jws(obj, self._get_nonce(url, new_nonce_url), url, acme_version)
        kwargs.setdefault('headers', {'Content-Type': content_type})
        response = self._send_request('POST', url, data=data, **kwargs)
        response = self._check_response(response, content_type=content_type)
        self._add_nonce(response)
        return response
