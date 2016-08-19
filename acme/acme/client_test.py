"""Tests for acme.client."""
import datetime
import json
import unittest

from six.moves import http_client  # pylint: disable=import-error

import mock
import requests

from acme import challenges
from acme import errors
from acme import jose
from acme import jws as acme_jws
from acme import messages
from acme import messages_test
from acme import test_util


CERT_DER = test_util.load_vector('cert.der')
KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))
KEY2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))


class ClientTest(unittest.TestCase):
    """Tests for  acme.client.Client."""
    # pylint: disable=too-many-instance-attributes,too-many-public-methods

    def setUp(self):
        self.response = mock.MagicMock(
            ok=True, status_code=http_client.OK, headers={}, links={})
        self.net = mock.MagicMock()
        self.net.post.return_value = self.response
        self.net.get.return_value = self.response

        self.directory = messages.Directory({
            messages.NewRegistration:
                'https://www.letsencrypt-demo.org/acme/new-reg',
            messages.Revocation:
                'https://www.letsencrypt-demo.org/acme/revoke-cert',
            messages.NewAuthorization:
                'https://www.letsencrypt-demo.org/acme/new-authz',
        })

        from acme.client import Client
        self.client = Client(
            directory=self.directory, key=KEY, alg=jose.RS256, net=self.net)

        self.identifier = messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value='example.com')

        # Registration
        self.contact = ('mailto:cert-admin@example.com', 'tel:+12025551212')
        reg = messages.Registration(
            contact=self.contact, key=KEY.public_key())
        self.new_reg = messages.NewRegistration(**dict(reg))
        self.regr = messages.RegistrationResource(
            body=reg, uri='https://www.letsencrypt-demo.org/acme/reg/1',
            new_authzr_uri='https://www.letsencrypt-demo.org/acme/new-reg',
            terms_of_service='https://www.letsencrypt-demo.org/tos')

        # Authorization
        authzr_uri = 'https://www.letsencrypt-demo.org/acme/authz/1'
        challb = messages.ChallengeBody(
            uri=(authzr_uri + '/1'), status=messages.STATUS_VALID,
            chall=challenges.DNS(token=jose.b64decode(
                'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA')))
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
            body=messages_test.CERT, authzrs=(self.authzr,),
            uri='https://www.letsencrypt-demo.org/acme/cert/1',
            cert_chain_uri='https://www.letsencrypt-demo.org/ca')

    def test_init_downloads_directory(self):
        uri = 'http://www.letsencrypt-demo.org/directory'
        from acme.client import Client
        self.client = Client(
            directory=uri, key=KEY, alg=jose.RS256, net=self.net)
        self.net.get.assert_called_once_with(uri)

    def test_register(self):
        # "Instance of 'Field' has no to_json/update member" bug:
        # pylint: disable=no-member
        self.response.status_code = http_client.CREATED
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers['Location'] = self.regr.uri
        self.response.links.update({
            'next': {'url': self.regr.new_authzr_uri},
            'terms-of-service': {'url': self.regr.terms_of_service},
        })

        self.assertEqual(self.regr, self.client.register(self.new_reg))
        # TODO: test POST call arguments

    def test_register_missing_next(self):
        self.response.status_code = http_client.CREATED
        self.assertRaises(
            errors.ClientError, self.client.register, self.new_reg)

    def test_update_registration(self):
        # "Instance of 'Field' has no to_json/update member" bug:
        # pylint: disable=no-member
        self.response.headers['Location'] = self.regr.uri
        self.response.json.return_value = self.regr.body.to_json()
        self.assertEqual(self.regr, self.client.update_registration(self.regr))
        # TODO: test POST call arguments

        # TODO: split here and separate test
        self.response.json.return_value = self.regr.body.update(
            contact=()).to_json()
        self.assertRaises(
            errors.UnexpectedUpdate, self.client.update_registration, self.regr)

    def test_query_registration(self):
        self.response.json.return_value = self.regr.body.to_json()
        self.assertEqual(self.regr, self.client.query_registration(self.regr))

    def test_query_registration_updates_new_authzr_uri(self):
        self.response.json.return_value = self.regr.body.to_json()
        self.response.links = {'next': {'url': 'UPDATED'}}
        self.assertEqual(
            'UPDATED',
            self.client.query_registration(self.regr).new_authzr_uri)

    def test_agree_to_tos(self):
        self.client.update_registration = mock.Mock()
        self.client.agree_to_tos(self.regr)
        regr = self.client.update_registration.call_args[0][0]
        self.assertEqual(self.regr.terms_of_service, regr.body.agreement)

    def _prepare_response_for_request_challenges(self):
        self.response.status_code = http_client.CREATED
        self.response.headers['Location'] = self.authzr.uri
        self.response.json.return_value = self.authz.to_json()
        self.response.links = {
            'next': {'url': self.authzr.new_cert_uri},
        }

    def test_request_challenges(self):
        self._prepare_response_for_request_challenges()
        self.client.request_challenges(self.identifier)
        self.net.post.assert_called_once_with(
            self.directory.new_authz,
            messages.NewAuthorization(identifier=self.identifier))

    def test_requets_challenges_custom_uri(self):
        self._prepare_response_for_request_challenges()
        self.client.request_challenges(self.identifier, 'URI')
        self.net.post.assert_called_once_with('URI', mock.ANY)

    def test_request_challenges_unexpected_update(self):
        self._prepare_response_for_request_challenges()
        self.response.json.return_value = self.authz.update(
            identifier=self.identifier.update(value='foo')).to_json()
        self.assertRaises(
            errors.UnexpectedUpdate, self.client.request_challenges,
            self.identifier, self.authzr.uri)

    def test_request_challenges_missing_next(self):
        self.response.status_code = http_client.CREATED
        self.assertRaises(errors.ClientError, self.client.request_challenges,
                          self.identifier)

    def test_request_domain_challenges(self):
        self.client.request_challenges = mock.MagicMock()
        self.assertEqual(
            self.client.request_challenges(self.identifier),
            self.client.request_domain_challenges('example.com'))

    def test_request_domain_challenges_custom_uri(self):
        self.client.request_challenges = mock.MagicMock()
        self.assertEqual(
            self.client.request_challenges(self.identifier, 'URI'),
            self.client.request_domain_challenges('example.com', 'URI'))

    def test_answer_challenge(self):
        self.response.links['up'] = {'url': self.challr.authzr_uri}
        self.response.json.return_value = self.challr.body.to_json()

        chall_response = challenges.DNSResponse(validation=None)

        self.client.answer_challenge(self.challr.body, chall_response)

        # TODO: split here and separate test
        self.assertRaises(errors.UnexpectedUpdate, self.client.answer_challenge,
                          self.challr.body.update(uri='foo'), chall_response)

    def test_answer_challenge_missing_next(self):
        self.assertRaises(
            errors.ClientError, self.client.answer_challenge,
            self.challr.body, challenges.DNSResponse(validation=None))

    def test_retry_after_date(self):
        self.response.headers['Retry-After'] = 'Fri, 31 Dec 1999 23:59:59 GMT'
        self.assertEqual(
            datetime.datetime(1999, 12, 31, 23, 59, 59),
            self.client.retry_after(response=self.response, default=10))

    @mock.patch('acme.client.datetime')
    def test_retry_after_invalid(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.response.headers['Retry-After'] = 'foooo'
        self.assertEqual(
            datetime.datetime(2015, 3, 27, 0, 0, 10),
            self.client.retry_after(response=self.response, default=10))

    @mock.patch('acme.client.datetime')
    def test_retry_after_overflow(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta
        dt_mock.datetime.side_effect = datetime.datetime

        self.response.headers['Retry-After'] = "Tue, 116 Feb 2016 11:50:00 MST"
        self.assertEqual(
            datetime.datetime(2015, 3, 27, 0, 0, 10),
            self.client.retry_after(response=self.response, default=10))

    @mock.patch('acme.client.datetime')
    def test_retry_after_seconds(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.response.headers['Retry-After'] = '50'
        self.assertEqual(
            datetime.datetime(2015, 3, 27, 0, 0, 50),
            self.client.retry_after(response=self.response, default=10))

    @mock.patch('acme.client.datetime')
    def test_retry_after_missing(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.assertEqual(
            datetime.datetime(2015, 3, 27, 0, 0, 10),
            self.client.retry_after(response=self.response, default=10))

    def test_poll(self):
        self.response.json.return_value = self.authzr.body.to_json()
        self.assertEqual((self.authzr, self.response),
                         self.client.poll(self.authzr))

        # TODO: split here and separate test
        self.response.json.return_value = self.authz.update(
            identifier=self.identifier.update(value='foo')).to_json()
        self.assertRaises(
            errors.UnexpectedUpdate, self.client.poll, self.authzr)

    def test_request_issuance(self):
        self.response.content = CERT_DER
        self.response.headers['Location'] = self.certr.uri
        self.response.links['up'] = {'url': self.certr.cert_chain_uri}
        self.assertEqual(self.certr, self.client.request_issuance(
            messages_test.CSR, (self.authzr,)))
        # TODO: check POST args

    def test_request_issuance_missing_up(self):
        self.response.content = CERT_DER
        self.response.headers['Location'] = self.certr.uri
        self.assertEqual(
            self.certr.update(cert_chain_uri=None),
            self.client.request_issuance(messages_test.CSR, (self.authzr,)))

    def test_request_issuance_missing_location(self):
        self.assertRaises(
            errors.ClientError, self.client.request_issuance,
            messages_test.CSR, (self.authzr,))

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

            if len(authzr.retries) == 1:  # no more retries
                done = mock.MagicMock(uri=authzr.uri, times=authzr.times)
                done.body.status = authzr.retries[0]
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
        self.client.poll = mock.MagicMock(side_effect=poll)

        mintime = 7

        def retry_after(response, default):
            # pylint: disable=missing-docstring
            # check that poll_and_request_issuance correctly passes mintime
            self.assertEqual(default, mintime)
            return clock.dt + datetime.timedelta(seconds=response)
        self.client.retry_after = mock.MagicMock(side_effect=retry_after)

        def request_issuance(csr, authzrs):  # pylint: disable=missing-docstring
            return csr, authzrs
        self.client.request_issuance = mock.MagicMock(
            side_effect=request_issuance)

        csr = mock.MagicMock()
        authzrs = (
            mock.MagicMock(uri='a', times=[], retries=(
                8, 20, 30, messages.STATUS_VALID)),
            mock.MagicMock(uri='b', times=[], retries=(
                5, messages.STATUS_VALID)),
        )

        cert, updated_authzrs = self.client.poll_and_request_issuance(
            csr, authzrs, mintime=mintime,
            # make sure that max_attempts is per-authorization, rather
            # than global
            max_attempts=max(len(authzrs[0].retries), len(authzrs[1].retries)))
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

        # CA sets invalid | TODO: move to a separate test
        invalid_authzr = mock.MagicMock(
            times=[], retries=[messages.STATUS_INVALID])
        self.assertRaises(
            errors.PollError, self.client.poll_and_request_issuance,
            csr, authzrs=(invalid_authzr,), mintime=mintime)

        # exceeded max_attemps | TODO: move to a separate test
        self.assertRaises(
            errors.PollError, self.client.poll_and_request_issuance,
            csr, authzrs, mintime=mintime, max_attempts=2)

    def test_check_cert(self):
        self.response.headers['Location'] = self.certr.uri
        self.response.content = CERT_DER
        self.assertEqual(self.certr.update(body=messages_test.CERT),
                         self.client.check_cert(self.certr))

        # TODO: split here and separate test
        self.response.headers['Location'] = 'foo'
        self.assertRaises(
            errors.UnexpectedUpdate, self.client.check_cert, self.certr)

    def test_check_cert_missing_location(self):
        self.response.content = CERT_DER
        self.assertRaises(
            errors.ClientError, self.client.check_cert, self.certr)

    def test_refresh(self):
        self.client.check_cert = mock.MagicMock()
        self.assertEqual(
            self.client.check_cert(self.certr), self.client.refresh(self.certr))

    def test_fetch_chain_no_up_link(self):
        self.assertEqual([], self.client.fetch_chain(self.certr.update(
            cert_chain_uri=None)))

    def test_fetch_chain_single(self):
        # pylint: disable=protected-access
        self.client._get_cert = mock.MagicMock()
        self.client._get_cert.return_value = (
            mock.MagicMock(links={}), "certificate")
        self.assertEqual([self.client._get_cert(self.certr.cert_chain_uri)[1]],
                         self.client.fetch_chain(self.certr))

    def test_fetch_chain_max(self):
        # pylint: disable=protected-access
        up_response = mock.MagicMock(links={'up': {'url': 'http://cert'}})
        noup_response = mock.MagicMock(links={})
        self.client._get_cert = mock.MagicMock()
        self.client._get_cert.side_effect = [
            (up_response, "cert")] * 9 + [(noup_response, "last_cert")]
        chain = self.client.fetch_chain(self.certr, max_length=10)
        self.assertEqual(chain, ["cert"] * 9 + ["last_cert"])

    def test_fetch_chain_too_many(self):  # recursive
        # pylint: disable=protected-access
        response = mock.MagicMock(links={'up': {'url': 'http://cert'}})
        self.client._get_cert = mock.MagicMock()
        self.client._get_cert.return_value = (response, "certificate")
        self.assertRaises(errors.Error, self.client.fetch_chain, self.certr)

    def test_revoke(self):
        self.client.revoke(self.certr.body)
        self.net.post.assert_called_once_with(
            self.directory[messages.Revocation], mock.ANY, content_type=None)

    def test_revoke_bad_status_raises_error(self):
        self.response.status_code = http_client.METHOD_NOT_ALLOWED
        self.assertRaises(errors.ClientError, self.client.revoke, self.certr)


class ClientNetworkTest(unittest.TestCase):
    """Tests for acme.client.ClientNetwork."""

    def setUp(self):
        self.verify_ssl = mock.MagicMock()
        self.wrap_in_jws = mock.MagicMock(return_value=mock.sentinel.wrapped)

        from acme.client import ClientNetwork
        self.net = ClientNetwork(
            key=KEY, alg=jose.RS256, verify_ssl=self.verify_ssl,
            user_agent='acme-python-test')

        self.response = mock.MagicMock(ok=True, status_code=http_client.OK)
        self.response.headers = {}
        self.response.links = {}

    def test_init(self):
        self.assertTrue(self.net.verify_ssl is self.verify_ssl)

    def test_wrap_in_jws(self):
        class MockJSONDeSerializable(jose.JSONDeSerializable):
            # pylint: disable=missing-docstring
            def __init__(self, value):
                self.value = value

            def to_partial_json(self):
                return {'foo': self.value}

            @classmethod
            def from_json(cls, value):
                pass  # pragma: no cover

        # pylint: disable=protected-access
        jws_dump = self.net._wrap_in_jws(
            MockJSONDeSerializable('foo'), nonce=b'Tg')
        jws = acme_jws.JWS.json_loads(jws_dump)
        self.assertEqual(json.loads(jws.payload.decode()), {'foo': 'foo'})
        self.assertEqual(jws.signature.combined.nonce, b'Tg')

    def test_check_response_not_ok_jobj_no_error(self):
        self.response.ok = False
        self.response.json.return_value = {}
        with mock.patch('acme.client.messages.Error.from_json') as from_json:
            from_json.side_effect = jose.DeserializationError
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
            # pylint: disable=protected-access,no-value-for-parameter
            self.assertEqual(
                self.response, self.net._check_response(self.response))

    def test_check_response_jobj(self):
        self.response.json.return_value = {}
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access,no-value-for-parameter
            self.assertEqual(
                self.response, self.net._check_response(self.response))

    def test_send_request(self):
        self.net.session = mock.MagicMock()
        self.net.session.request.return_value = self.response
        # pylint: disable=protected-access
        self.assertEqual(self.response, self.net._send_request(
            'HEAD', 'http://example.com/', 'foo', bar='baz'))
        self.net.session.request.assert_called_once_with(
            'HEAD', 'http://example.com/', 'foo',
            headers=mock.ANY, verify=mock.ANY, bar='baz')

    def test_send_request_verify_ssl(self):
        # pylint: disable=protected-access
        for verify in True, False:
            self.net.session = mock.MagicMock()
            self.net.session.request.return_value = self.response
            self.net.verify_ssl = verify
            # pylint: disable=protected-access
            self.assertEqual(
                self.response,
                self.net._send_request('GET', 'http://example.com/'))
            self.net.session.request.assert_called_once_with(
                'GET', 'http://example.com/', verify=verify, headers=mock.ANY)

    def test_send_request_user_agent(self):
        self.net.session = mock.MagicMock()
        # pylint: disable=protected-access
        self.net._send_request('GET', 'http://example.com/',
                               headers={'bar': 'baz'})
        self.net.session.request.assert_called_once_with(
            'GET', 'http://example.com/', verify=mock.ANY,
            headers={'User-Agent': 'acme-python-test', 'bar': 'baz'})

        self.net._send_request('GET', 'http://example.com/',
                               headers={'User-Agent': 'foo2'})
        self.net.session.request.assert_called_with(
            'GET', 'http://example.com/',
            verify=mock.ANY, headers={'User-Agent': 'foo2'})

    def test_del(self):
        sess = mock.MagicMock()
        self.net.session = sess
        del self.net
        sess.close.assert_called_once_with()

    @mock.patch('acme.client.requests')
    def test_requests_error_passthrough(self, mock_requests):
        mock_requests.exceptions = requests.exceptions
        mock_requests.request.side_effect = requests.exceptions.RequestException
        # pylint: disable=protected-access
        self.assertRaises(requests.exceptions.RequestException,
                          self.net._send_request, 'GET', 'uri')


class ClientNetworkWithMockedResponseTest(unittest.TestCase):
    """Tests for acme.client.ClientNetwork which mock out response."""
    # pylint: disable=too-many-instance-attributes

    def setUp(self):
        from acme.client import ClientNetwork
        self.net = ClientNetwork(key=None, alg=None)

        self.response = mock.MagicMock(ok=True, status_code=http_client.OK)
        self.response.headers = {}
        self.response.links = {}
        self.checked_response = mock.MagicMock()
        self.obj = mock.MagicMock()
        self.wrapped_obj = mock.MagicMock()
        self.content_type = mock.sentinel.content_type

        self.all_nonces = [jose.b64encode(b'Nonce'), jose.b64encode(b'Nonce2')]
        self.available_nonces = self.all_nonces[:]

        def send_request(*args, **kwargs):
            # pylint: disable=unused-argument,missing-docstring
            if self.available_nonces:
                self.response.headers = {
                    self.net.REPLAY_NONCE_HEADER:
                    self.available_nonces.pop().decode()}
            else:
                self.response.headers = {}
            return self.response

        # pylint: disable=protected-access
        self.net._send_request = self.send_request = mock.MagicMock(
            side_effect=send_request)
        self.net._check_response = self.check_response
        self.net._wrap_in_jws = mock.MagicMock(return_value=self.wrapped_obj)

    def check_response(self, response, content_type):
        # pylint: disable=missing-docstring
        self.assertEqual(self.response, response)
        self.assertEqual(self.content_type, content_type)
        return self.checked_response

    def test_head(self):
        self.assertEqual(self.response, self.net.head(
            'http://example.com/', 'foo', bar='baz'))
        self.send_request.assert_called_once_with(
            'HEAD', 'http://example.com/', 'foo', bar='baz')

    def test_get(self):
        self.assertEqual(self.checked_response, self.net.get(
            'http://example.com/', content_type=self.content_type, bar='baz'))
        self.send_request.assert_called_once_with(
            'GET', 'http://example.com/', bar='baz')

    def test_post(self):
        # pylint: disable=protected-access
        self.assertEqual(self.checked_response, self.net.post(
            'uri', self.obj, content_type=self.content_type))
        self.net._wrap_in_jws.assert_called_once_with(
            self.obj, jose.b64decode(self.all_nonces.pop()))

        assert not self.available_nonces
        self.assertRaises(errors.MissingNonce, self.net.post,
                          'uri', self.obj, content_type=self.content_type)
        self.net._wrap_in_jws.assert_called_with(
            self.obj, jose.b64decode(self.all_nonces.pop()))

    def test_post_wrong_initial_nonce(self):  # HEAD
        self.available_nonces = [b'f', jose.b64encode(b'good')]
        self.assertRaises(errors.BadNonce, self.net.post, 'uri',
                          self.obj, content_type=self.content_type)

    def test_post_wrong_post_response_nonce(self):
        self.available_nonces = [jose.b64encode(b'good'), b'f']
        self.assertRaises(errors.BadNonce, self.net.post, 'uri',
                          self.obj, content_type=self.content_type)

    def test_head_get_post_error_passthrough(self):
        self.send_request.side_effect = requests.exceptions.RequestException
        for method in self.net.head, self.net.get:
            self.assertRaises(
                requests.exceptions.RequestException, method, 'GET', 'uri')
        self.assertRaises(requests.exceptions.RequestException,
                          self.net.post, 'uri', obj=self.obj)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
