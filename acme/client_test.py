"""Tests for acme.client."""
import datetime
import httplib
import os
import pkg_resources
import unittest

import M2Crypto
import mock
import requests

from acme import challenges
from acme import errors
from acme import jose
from acme import jws as acme_jws
from acme import messages


CERT = jose.ComparableX509(M2Crypto.X509.load_cert_string(
    pkg_resources.resource_string(
        'acme.jose', os.path.join('testdata', 'cert.der')),
    M2Crypto.X509.FORMAT_DER))
CSR = jose.ComparableX509(M2Crypto.X509.load_request_string(
    pkg_resources.resource_string(
        'acme.jose', os.path.join('testdata', 'csr.der')),
    M2Crypto.X509.FORMAT_DER))
KEY = jose.JWKRSA.load(pkg_resources.resource_string(
    'acme.jose', os.path.join('testdata', 'rsa512_key.pem')))
KEY2 = jose.JWKRSA.load(pkg_resources.resource_string(
    'acme.jose', os.path.join('testdata', 'rsa256_key.pem')))


class ClientTest(unittest.TestCase):
    """Tests for acme.client.Client."""

    # pylint: disable=too-many-instance-attributes,too-many-public-methods

    def setUp(self):
        self.verify_ssl = mock.MagicMock()
        self.wrap_in_jws = mock.MagicMock(return_value=mock.sentinel.wrapped)

        from acme.client import Client
        self.net = Client(
            new_reg_uri='https://www.letsencrypt-demo.org/acme/new-reg',
            key=KEY, alg=jose.RS256, verify_ssl=self.verify_ssl)
        self.nonce = jose.b64encode('Nonce')
        self.net._nonces.add(self.nonce)  # pylint: disable=protected-access

        self.response = mock.MagicMock(ok=True, status_code=httplib.OK)
        self.response.headers = {}
        self.response.links = {}

        self.post = mock.MagicMock(return_value=self.response)
        self.get = mock.MagicMock(return_value=self.response)

        self.identifier = messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value='example.com')

        # Registration
        self.contact = ('mailto:cert-admin@example.com', 'tel:+12025551212')
        reg = messages.Registration(
            contact=self.contact, key=KEY.public(), recovery_token='t')
        self.regr = messages.RegistrationResource(
            body=reg, uri='https://www.letsencrypt-demo.org/acme/reg/1',
            new_authzr_uri='https://www.letsencrypt-demo.org/acme/new-reg',
            terms_of_service='https://www.letsencrypt-demo.org/tos')

        # Authorization
        authzr_uri = 'https://www.letsencrypt-demo.org/acme/authz/1'
        challb = messages.ChallengeBody(
            uri=(authzr_uri + '/1'), status=messages.STATUS_VALID,
            chall=challenges.DNS(token='foo'))
        self.challr = messages.ChallengeResource(
            body=challb, authzr_uri=authzr_uri)
        self.authz = messages.Authorization(
            identifier=messages.Identifier(
                typ=messages.IDENTIFIER_FQDN, value='example.com'),
            challenges=(challb,), combinations=None)
        self.authzr = messages.AuthorizationResource(
            body=self.authz, uri=authzr_uri,
            new_cert_uri='https://www.letsencrypt-demo.org/acme/new-cert')

        # Request issuance
        self.certr = messages.CertificateResource(
            body=CERT, authzrs=(self.authzr,),
            uri='https://www.letsencrypt-demo.org/acme/cert/1',
            cert_chain_uri='https://www.letsencrypt-demo.org/ca')

    def _mock_post_get(self):
        # pylint: disable=protected-access
        self.net._post = self.post
        self.net._get = self.get

    def test_init(self):
        self.assertTrue(self.net.verify_ssl is self.verify_ssl)

    def test_wrap_in_jws(self):
        class MockJSONDeSerializable(jose.JSONDeSerializable):
            # pylint: disable=missing-docstring
            def __init__(self, value):
                self.value = value
            def to_partial_json(self):
                return self.value
            @classmethod
            def from_json(cls, value):
                pass  # pragma: no cover
        # pylint: disable=protected-access
        jws_dump = self.net._wrap_in_jws(
            MockJSONDeSerializable('foo'), nonce='Tg')
        jws = acme_jws.JWS.json_loads(jws_dump)
        self.assertEqual(jws.payload, '"foo"')
        self.assertEqual(jws.signature.combined.nonce, 'Tg')
        # TODO: check that nonce is in protected header

    def test_check_response_not_ok_jobj_no_error(self):
        self.response.ok = False
        self.response.json.return_value = {}
        # pylint: disable=protected-access
        self.assertRaises(
            errors.ClientError, self.net._check_response, self.response)

    def test_check_response_not_ok_jobj_error(self):
        self.response.ok = False
        self.response.json.return_value = messages.Error(
            detail='foo', typ='serverInternal', title='some title').to_json()
        # pylint: disable=protected-access
        self.assertRaises(
            messages.Error, self.net._check_response, self.response)

    def test_check_response_not_ok_no_jobj(self):
        self.response.ok = False
        self.response.json.side_effect = ValueError
        # pylint: disable=protected-access
        self.assertRaises(
            errors.ClientError, self.net._check_response, self.response)

    def test_check_response_ok_no_jobj_ct_required(self):
        self.response.json.side_effect = ValueError
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access
            self.assertRaises(
                errors.ClientError, self.net._check_response, self.response,
                content_type=self.net.JSON_CONTENT_TYPE)

    def test_check_response_ok_no_jobj_no_ct(self):
        self.response.json.side_effect = ValueError
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access
            self.net._check_response(self.response)

    def test_check_response_jobj(self):
        self.response.json.return_value = {}
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access
            self.net._check_response(self.response)

    @mock.patch('acme.client.requests')
    def test_get_requests_error_passthrough(self, requests_mock):
        requests_mock.exceptions = requests.exceptions
        requests_mock.get.side_effect = requests.exceptions.RequestException
        # pylint: disable=protected-access
        self.assertRaises(errors.ClientError, self.net._get, 'uri')

    @mock.patch('acme.client.requests')
    def test_get(self, requests_mock):
        # pylint: disable=protected-access
        self.net._check_response = mock.MagicMock()
        self.net._get('uri', content_type='ct')
        self.net._check_response.assert_called_once_with(
            requests_mock.get('uri'), content_type='ct')

    def _mock_wrap_in_jws(self):
        # pylint: disable=protected-access
        self.net._wrap_in_jws = self.wrap_in_jws

    @mock.patch('acme.client.requests')
    def test_post_requests_error_passthrough(self, requests_mock):
        requests_mock.exceptions = requests.exceptions
        requests_mock.post.side_effect = requests.exceptions.RequestException
        # pylint: disable=protected-access
        self._mock_wrap_in_jws()
        self.assertRaises(
            errors.ClientError, self.net._post, 'uri', mock.sentinel.obj)

    @mock.patch('acme.client.requests')
    def test_post(self, requests_mock):
        # pylint: disable=protected-access
        self.net._check_response = mock.MagicMock()
        self._mock_wrap_in_jws()
        requests_mock.post().headers = {
            self.net.REPLAY_NONCE_HEADER: self.nonce}
        self.net._post('uri', mock.sentinel.obj, content_type='ct')
        self.net._check_response.assert_called_once_with(
            requests_mock.post('uri', mock.sentinel.wrapped), content_type='ct')

    @mock.patch('acme.client.requests')
    def test_post_replay_nonce_handling(self, requests_mock):
        # pylint: disable=protected-access
        self.net._check_response = mock.MagicMock()
        self._mock_wrap_in_jws()

        self.net._nonces.clear()
        self.assertRaises(
            errors.ClientError, self.net._post, 'uri', mock.sentinel.obj)

        nonce2 = jose.b64encode('Nonce2')
        requests_mock.head('uri').headers = {
            self.net.REPLAY_NONCE_HEADER: nonce2}
        requests_mock.post('uri').headers = {
            self.net.REPLAY_NONCE_HEADER: self.nonce}

        self.net._post('uri', mock.sentinel.obj)

        requests_mock.head.assert_called_with('uri')
        self.wrap_in_jws.assert_called_once_with(mock.sentinel.obj, nonce2)
        self.assertEqual(self.net._nonces, set([self.nonce]))

        # wrong nonce
        requests_mock.post('uri').headers = {self.net.REPLAY_NONCE_HEADER: 'F'}
        self.assertRaises(
            errors.ClientError, self.net._post, 'uri', mock.sentinel.obj)

    @mock.patch('acme.client.requests')
    def test_get_post_verify_ssl(self, requests_mock):
        # pylint: disable=protected-access
        self._mock_wrap_in_jws()
        self.net._check_response = mock.MagicMock()

        for verify_ssl in [True, False]:
            self.net.verify_ssl = verify_ssl
            self.net._get('uri')
            self.net._nonces.add('N')
            requests_mock.post().headers = {
                self.net.REPLAY_NONCE_HEADER: self.nonce}
            self.net._post('uri', mock.sentinel.obj)
            requests_mock.get.assert_called_once_with('uri', verify=verify_ssl)
            requests_mock.post.assert_called_with(
                'uri', data=mock.sentinel.wrapped, verify=verify_ssl)
            requests_mock.reset_mock()

    def test_register(self):
        self.response.status_code = httplib.CREATED
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers['Location'] = self.regr.uri
        self.response.links.update({
            'next': {'url': self.regr.new_authzr_uri},
            'terms-of-service': {'url': self.regr.terms_of_service},
        })

        self._mock_post_get()
        self.assertEqual(self.regr, self.net.register(self.contact))
        # TODO: test POST call arguments

        # TODO: split here and separate test
        reg_wrong_key = self.regr.body.update(key=KEY2.public())
        self.response.json.return_value = reg_wrong_key.to_json()
        self.assertRaises(
            errors.UnexpectedUpdate, self.net.register, self.contact)

    def test_register_missing_next(self):
        self.response.status_code = httplib.CREATED
        self._mock_post_get()
        self.assertRaises(
            errors.ClientError, self.net.register, self.regr.body)

    def test_update_registration(self):
        self.response.headers['Location'] = self.regr.uri
        self.response.json.return_value = self.regr.body.to_json()
        self._mock_post_get()
        self.assertEqual(self.regr, self.net.update_registration(self.regr))

        # TODO: split here and separate test
        self.response.json.return_value = self.regr.body.update(
            contact=()).to_json()
        self.assertRaises(
            errors.UnexpectedUpdate, self.net.update_registration, self.regr)

    def test_agree_to_tos(self):
        self.net.update_registration = mock.Mock()
        self.net.agree_to_tos(self.regr)
        regr = self.net.update_registration.call_args[0][0]
        self.assertEqual(self.regr.terms_of_service, regr.body.agreement)

    def test_request_challenges(self):
        self.response.status_code = httplib.CREATED
        self.response.headers['Location'] = self.authzr.uri
        self.response.json.return_value = self.authz.to_json()
        self.response.links = {
            'next': {'url': self.authzr.new_cert_uri},
        }

        self._mock_post_get()
        self.net.request_challenges(self.identifier, self.authzr.uri)
        # TODO: test POST call arguments

        # TODO: split here and separate test
        self.response.json.return_value = self.authz.update(
            identifier=self.identifier.update(value='foo')).to_json()
        self.assertRaises(errors.UnexpectedUpdate, self.net.request_challenges,
                          self.identifier, self.authzr.uri)

    def test_request_challenges_missing_next(self):
        self.response.status_code = httplib.CREATED
        self._mock_post_get()
        self.assertRaises(
            errors.ClientError, self.net.request_challenges,
            self.identifier, self.regr)

    def test_request_domain_challenges(self):
        self.net.request_challenges = mock.MagicMock()
        self.assertEqual(
            self.net.request_challenges(self.identifier),
            self.net.request_domain_challenges('example.com', self.regr))

    def test_answer_challenge(self):
        self.response.links['up'] = {'url': self.challr.authzr_uri}
        self.response.json.return_value = self.challr.body.to_json()

        chall_response = challenges.DNSResponse()

        self._mock_post_get()
        self.net.answer_challenge(self.challr.body, chall_response)

        # TODO: split here and separate test
        self.assertRaises(errors.UnexpectedUpdate, self.net.answer_challenge,
                          self.challr.body.update(uri='foo'), chall_response)

    def test_answer_challenge_missing_next(self):
        self._mock_post_get()
        self.assertRaises(errors.ClientError, self.net.answer_challenge,
                          self.challr.body, challenges.DNSResponse())

    def test_retry_after_date(self):
        self.response.headers['Retry-After'] = 'Fri, 31 Dec 1999 23:59:59 GMT'
        self.assertEqual(
            datetime.datetime(1999, 12, 31, 23, 59, 59),
            self.net.retry_after(response=self.response, default=10))

    @mock.patch('acme.client.datetime')
    def test_retry_after_invalid(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.response.headers['Retry-After'] = 'foooo'
        self.assertEqual(
            datetime.datetime(2015, 3, 27, 0, 0, 10),
            self.net.retry_after(response=self.response, default=10))

    @mock.patch('acme.client.datetime')
    def test_retry_after_seconds(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.response.headers['Retry-After'] = '50'
        self.assertEqual(
            datetime.datetime(2015, 3, 27, 0, 0, 50),
            self.net.retry_after(response=self.response, default=10))

    @mock.patch('acme.client.datetime')
    def test_retry_after_missing(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.assertEqual(
            datetime.datetime(2015, 3, 27, 0, 0, 10),
            self.net.retry_after(response=self.response, default=10))

    def test_poll(self):
        self.response.json.return_value = self.authzr.body.to_json()
        self._mock_post_get()
        self.assertEqual((self.authzr, self.response),
                         self.net.poll(self.authzr))

        # TODO: split here and separate test
        self.response.json.return_value = self.authz.update(
            identifier=self.identifier.update(value='foo')).to_json()
        self.assertRaises(errors.UnexpectedUpdate, self.net.poll, self.authzr)

    def test_request_issuance(self):
        self.response.content = CERT.as_der()
        self.response.headers['Location'] = self.certr.uri
        self.response.links['up'] = {'url': self.certr.cert_chain_uri}
        self._mock_post_get()
        self.assertEqual(
            self.certr, self.net.request_issuance(CSR, (self.authzr,)))
        # TODO: check POST args

    def test_request_issuance_missing_up(self):
        self.response.content = CERT.as_der()
        self.response.headers['Location'] = self.certr.uri
        self._mock_post_get()
        self.assertEqual(
            self.certr.update(cert_chain_uri=None),
            self.net.request_issuance(CSR, (self.authzr,)))

    def test_request_issuance_missing_location(self):
        self._mock_post_get()
        self.assertRaises(
            errors.ClientError, self.net.request_issuance,
            CSR, (self.authzr,))

    @mock.patch('acme.client.datetime')
    @mock.patch('acme.client.time')
    def test_poll_and_request_issuance(self, time_mock, dt_mock):
        # clock.dt | pylint: disable=no-member
        clock = mock.MagicMock(dt=datetime.datetime(2015, 3, 27))

        def sleep(seconds):
            """increment clock"""
            clock.dt += datetime.timedelta(seconds=seconds)
        time_mock.sleep.side_effect = sleep

        def now():
            """return current clock value"""
            return clock.dt
        dt_mock.datetime.now.side_effect = now
        dt_mock.timedelta = datetime.timedelta

        def poll(authzr):  # pylint: disable=missing-docstring
            # record poll start time based on the current clock value
            authzr.times.append(clock.dt)

            # suppose it takes 2 seconds for server to produce the
            # result, increment clock
            clock.dt += datetime.timedelta(seconds=2)

            if not authzr.retries:  # no more retries
                done = mock.MagicMock(uri=authzr.uri, times=authzr.times)
                done.body.status = messages.STATUS_VALID
                return done, []

            # response (2nd result tuple element) is reduced to only
            # Retry-After header contents represented as integer
            # seconds; authzr.retries is a list of Retry-After
            # headers, head(retries) is peeled of as a current
            # Retry-After header, and tail(retries) is persisted for
            # later poll() calls
            return (mock.MagicMock(retries=authzr.retries[1:],
                                   uri=authzr.uri + '.', times=authzr.times),
                    authzr.retries[0])
        self.net.poll = mock.MagicMock(side_effect=poll)

        mintime = 7

        def retry_after(response, default):  # pylint: disable=missing-docstring
            # check that poll_and_request_issuance correctly passes mintime
            self.assertEqual(default, mintime)
            return clock.dt + datetime.timedelta(seconds=response)
        self.net.retry_after = mock.MagicMock(side_effect=retry_after)

        def request_issuance(csr, authzrs):  # pylint: disable=missing-docstring
            return csr, authzrs
        self.net.request_issuance = mock.MagicMock(side_effect=request_issuance)

        csr = mock.MagicMock()
        authzrs = (
            mock.MagicMock(uri='a', times=[], retries=(8, 20, 30)),
            mock.MagicMock(uri='b', times=[], retries=(5,)),
        )

        cert, updated_authzrs = self.net.poll_and_request_issuance(
            csr, authzrs, mintime=mintime)
        self.assertTrue(cert[0] is csr)
        self.assertTrue(cert[1] is updated_authzrs)
        self.assertEqual(updated_authzrs[0].uri, 'a...')
        self.assertEqual(updated_authzrs[1].uri, 'b.')
        self.assertEqual(updated_authzrs[0].times, [
            datetime.datetime(2015, 3, 27),
            # a is scheduled for 10, but b is polling [9..11), so it
            # will be picked up as soon as b is finished, without
            # additional sleeping
            datetime.datetime(2015, 3, 27, 0, 0, 11),
            datetime.datetime(2015, 3, 27, 0, 0, 33),
            datetime.datetime(2015, 3, 27, 0, 1, 5),
        ])
        self.assertEqual(updated_authzrs[1].times, [
            datetime.datetime(2015, 3, 27, 0, 0, 2),
            datetime.datetime(2015, 3, 27, 0, 0, 9),
        ])
        self.assertEqual(clock.dt, datetime.datetime(2015, 3, 27, 0, 1, 7))

    def test_check_cert(self):
        self.response.headers['Location'] = self.certr.uri
        self.response.content = CERT.as_der()
        self._mock_post_get()
        self.assertEqual(
            self.certr.update(body=CERT), self.net.check_cert(self.certr))

        # TODO: split here and separate test
        self.response.headers['Location'] = 'foo'
        self.assertRaises(
            errors.UnexpectedUpdate, self.net.check_cert, self.certr)

    def test_check_cert_missing_location(self):
        self.response.content = CERT.as_der()
        self._mock_post_get()
        self.assertRaises(errors.ClientError, self.net.check_cert, self.certr)

    def test_refresh(self):
        self.net.check_cert = mock.MagicMock()
        self.assertEqual(
            self.net.check_cert(self.certr), self.net.refresh(self.certr))

    def test_fetch_chain(self):
        # pylint: disable=protected-access
        self.net._get_cert = mock.MagicMock()
        self.net._get_cert.return_value = ("response", "certificate")
        self.assertEqual(self.net._get_cert(self.certr.cert_chain_uri)[1],
                         self.net.fetch_chain(self.certr))

    def test_fetch_chain_no_up_link(self):
        self.assertTrue(self.net.fetch_chain(self.certr.update(
            cert_chain_uri=None)) is None)

    def test_revoke(self):
        self._mock_post_get()
        self.net.revoke(self.certr.body)
        self.post.assert_called_once_with(messages.Revocation.url(
            self.net.new_reg_uri), mock.ANY)

    def test_revoke_bad_status_raises_error(self):
        self.response.status_code = httplib.METHOD_NOT_ALLOWED
        self._mock_post_get()
        self.assertRaises(errors.ClientError, self.net.revoke, self.certr)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
