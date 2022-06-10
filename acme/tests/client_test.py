"""Tests for acme.client."""
# pylint: disable=too-many-lines
import copy
import datetime
import http.client as http_client
import ipaddress
import json
import unittest
from typing import Dict
from unittest import mock

import josepy as jose
import OpenSSL
import requests

from acme import challenges
from acme import errors
from acme import jws as acme_jws
from acme import messages
from acme.mixins import VersionedLEACMEMixin
import messages_test
import test_util

CERT_DER = test_util.load_vector('cert.der')
CERT_SAN_PEM = test_util.load_vector('cert-san.pem')
CSR_SAN_PEM = test_util.load_vector('csr-san.pem')
CSR_MIXED_PEM = test_util.load_vector('csr-mixed.pem')
KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))
KEY2 = jose.JWKRSA.load(test_util.load_vector('rsa256_key.pem'))

DIRECTORY_V1 = messages.Directory({
    messages.NewRegistration:
        'https://www.letsencrypt-demo.org/acme/new-reg',
    messages.Revocation:
        'https://www.letsencrypt-demo.org/acme/revoke-cert',
    messages.NewAuthorization:
        'https://www.letsencrypt-demo.org/acme/new-authz',
    messages.CertificateRequest:
        'https://www.letsencrypt-demo.org/acme/new-cert',
})

DIRECTORY_V2 = messages.Directory({
    'newAccount': 'https://www.letsencrypt-demo.org/acme/new-account',
    'newNonce': 'https://www.letsencrypt-demo.org/acme/new-nonce',
    'newOrder': 'https://www.letsencrypt-demo.org/acme/new-order',
    'revokeCert': 'https://www.letsencrypt-demo.org/acme/revoke-cert',
})


class ClientTestBase(unittest.TestCase):
    """Base for tests in acme.client."""

    def setUp(self):
        self.response = mock.MagicMock(
            ok=True, status_code=http_client.OK, headers={}, links={})
        self.net = mock.MagicMock()
        self.net.post.return_value = self.response
        self.net.get.return_value = self.response

        self.identifier = messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value='example.com')

        # Registration
        self.contact = ('mailto:cert-admin@example.com', 'tel:+12025551212')
        reg = messages.Registration(
            contact=self.contact, key=KEY.public_key())
        the_arg: Dict = dict(reg)
        self.new_reg = messages.NewRegistration(**the_arg)
        self.regr = messages.RegistrationResource(
            body=reg, uri='https://www.letsencrypt-demo.org/acme/reg/1')

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
            body=self.authz, uri=authzr_uri)

        # Reason code for revocation
        self.rsn = 1


class BackwardsCompatibleClientV2Test(ClientTestBase):
    """Tests for  acme.client.BackwardsCompatibleClientV2."""

    def setUp(self):
        super().setUp()
        # contains a loaded cert
        self.certr = messages.CertificateResource(
            body=messages_test.CERT)

        loaded = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, CERT_SAN_PEM)
        wrapped = jose.ComparableX509(loaded)
        self.chain = [wrapped, wrapped]

        self.cert_pem = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, messages_test.CERT.wrapped).decode()

        single_chain = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, loaded).decode()
        self.chain_pem = single_chain + single_chain

        self.fullchain_pem = self.cert_pem + self.chain_pem

        self.orderr = messages.OrderResource(
            csr_pem=CSR_SAN_PEM)

    def _init(self):
        uri = 'http://www.letsencrypt-demo.org/directory'
        from acme.client import BackwardsCompatibleClientV2
        return BackwardsCompatibleClientV2(net=self.net,
            key=KEY, server=uri)

    def test_init_downloads_directory(self):
        uri = 'http://www.letsencrypt-demo.org/directory'
        from acme.client import BackwardsCompatibleClientV2
        BackwardsCompatibleClientV2(net=self.net,
            key=KEY, server=uri)
        self.net.get.assert_called_once_with(uri)

    def test_init_acme_version(self):
        self.response.json.return_value = DIRECTORY_V1.to_json()
        client = self._init()
        self.assertEqual(client.acme_version, 1)

        self.response.json.return_value = DIRECTORY_V2.to_json()
        client = self._init()
        self.assertEqual(client.acme_version, 2)

    def test_query_registration_client_v2(self):
        self.response.json.return_value = DIRECTORY_V2.to_json()
        client = self._init()
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers = {'Location': 'https://www.letsencrypt-demo.org/acme/reg/1'}
        self.assertEqual(self.regr, client.query_registration(self.regr))

    def test_forwarding(self):
        self.response.json.return_value = DIRECTORY_V1.to_json()
        client = self._init()
        self.assertEqual(client.directory, client.client.directory)
        self.assertEqual(client.key, KEY)
        self.assertEqual(client.deactivate_registration, client.client.deactivate_registration)
        self.assertRaises(AttributeError, client.__getattr__, 'nonexistent')
        self.assertRaises(AttributeError, client.__getattr__, 'new_account_and_tos')
        self.assertRaises(AttributeError, client.__getattr__, 'new_account')

    def test_new_account_and_tos(self):
        # v2 no tos
        self.response.json.return_value = DIRECTORY_V2.to_json()
        with mock.patch('acme.client.ClientV2') as mock_client:
            client = self._init()
            client.new_account_and_tos(self.new_reg)
            mock_client().new_account.assert_called_with(self.new_reg)

        # v2 tos good
        with mock.patch('acme.client.ClientV2') as mock_client:
            mock_client().directory.meta.__contains__.return_value = True
            client = self._init()
            client.new_account_and_tos(self.new_reg, lambda x: True)
            mock_client().new_account.assert_called_with(
                self.new_reg.update(terms_of_service_agreed=True))

        # v2 tos bad
        with mock.patch('acme.client.ClientV2') as mock_client:
            mock_client().directory.meta.__contains__.return_value = True
            client = self._init()
            def _tos_cb(tos):
                raise errors.Error
            self.assertRaises(errors.Error, client.new_account_and_tos,
                self.new_reg, _tos_cb)
            mock_client().new_account.assert_not_called()

        # v1 yes tos
        self.response.json.return_value = DIRECTORY_V1.to_json()
        with mock.patch('acme.client.Client') as mock_client:
            regr = mock.MagicMock(terms_of_service="TOS")
            mock_client().register.return_value = regr
            client = self._init()
            client.new_account_and_tos(self.new_reg)
            mock_client().register.assert_called_once_with(self.new_reg)
            mock_client().agree_to_tos.assert_called_once_with(regr)

        # v1 no tos
        with mock.patch('acme.client.Client') as mock_client:
            regr = mock.MagicMock(terms_of_service=None)
            mock_client().register.return_value = regr
            client = self._init()
            client.new_account_and_tos(self.new_reg)
            mock_client().register.assert_called_once_with(self.new_reg)
            mock_client().agree_to_tos.assert_not_called()

    @mock.patch('OpenSSL.crypto.load_certificate_request')
    @mock.patch('acme.crypto_util._pyopenssl_cert_or_req_all_names')
    def test_new_order_v1(self, mock__pyopenssl_cert_or_req_all_names,
        unused_mock_load_certificate_request):
        self.response.json.return_value = DIRECTORY_V1.to_json()
        mock__pyopenssl_cert_or_req_all_names.return_value = ['example.com', 'www.example.com']
        mock_csr_pem = mock.MagicMock()
        with mock.patch('acme.client.Client') as mock_client:
            mock_client().request_domain_challenges.return_value = mock.sentinel.auth
            client = self._init()
            orderr = client.new_order(mock_csr_pem)
            self.assertEqual(orderr.authorizations, [mock.sentinel.auth, mock.sentinel.auth])

    def test_new_order_v2(self):
        self.response.json.return_value = DIRECTORY_V2.to_json()
        mock_csr_pem = mock.MagicMock()
        with mock.patch('acme.client.ClientV2') as mock_client:
            client = self._init()
            client.new_order(mock_csr_pem)
            mock_client().new_order.assert_called_once_with(mock_csr_pem)

    @mock.patch('acme.client.Client')
    def test_finalize_order_v1_success(self, mock_client):
        self.response.json.return_value = DIRECTORY_V1.to_json()

        mock_client().request_issuance.return_value = self.certr
        mock_client().fetch_chain.return_value = self.chain

        deadline = datetime.datetime(9999, 9, 9)
        client = self._init()
        result = client.finalize_order(self.orderr, deadline)
        self.assertEqual(result.fullchain_pem, self.fullchain_pem)
        mock_client().fetch_chain.assert_called_once_with(self.certr)

    @mock.patch('acme.client.Client')
    def test_finalize_order_v1_fetch_chain_error(self, mock_client):
        self.response.json.return_value = DIRECTORY_V1.to_json()

        mock_client().request_issuance.return_value = self.certr
        mock_client().fetch_chain.return_value = self.chain
        mock_client().fetch_chain.side_effect = [errors.Error, self.chain]

        deadline = datetime.datetime(9999, 9, 9)
        client = self._init()
        result = client.finalize_order(self.orderr, deadline)
        self.assertEqual(result.fullchain_pem, self.fullchain_pem)
        self.assertEqual(mock_client().fetch_chain.call_count, 2)

    @mock.patch('acme.client.Client')
    def test_finalize_order_v1_timeout(self, mock_client):
        self.response.json.return_value = DIRECTORY_V1.to_json()

        mock_client().request_issuance.return_value = self.certr

        deadline = deadline = datetime.datetime.now() - datetime.timedelta(seconds=60)
        client = self._init()
        self.assertRaises(errors.TimeoutError, client.finalize_order,
            self.orderr, deadline)

    def test_finalize_order_v2(self):
        self.response.json.return_value = DIRECTORY_V2.to_json()
        mock_orderr = mock.MagicMock()
        mock_deadline = mock.MagicMock()
        with mock.patch('acme.client.ClientV2') as mock_client:
            client = self._init()
            client.finalize_order(mock_orderr, mock_deadline)
            mock_client().finalize_order.assert_called_once_with(mock_orderr, mock_deadline, False)

    def test_revoke(self):
        self.response.json.return_value = DIRECTORY_V1.to_json()
        with mock.patch('acme.client.Client') as mock_client:
            client = self._init()
            client.revoke(messages_test.CERT, self.rsn)
        mock_client().revoke.assert_called_once_with(messages_test.CERT, self.rsn)

        self.response.json.return_value = DIRECTORY_V2.to_json()
        with mock.patch('acme.client.ClientV2') as mock_client:
            client = self._init()
            client.revoke(messages_test.CERT, self.rsn)
        mock_client().revoke.assert_called_once_with(messages_test.CERT, self.rsn)

    def test_update_registration(self):
        self.response.json.return_value = DIRECTORY_V1.to_json()
        with mock.patch('acme.client.Client') as mock_client:
            client = self._init()
            client.update_registration(mock.sentinel.regr, None)
        mock_client().update_registration.assert_called_once_with(mock.sentinel.regr, None)

    # newNonce present means it will pick acme_version 2
    def test_external_account_required_true(self):
        self.response.json.return_value = messages.Directory({
            'newNonce': 'http://letsencrypt-test.com/acme/new-nonce',
            'meta': messages.Directory.Meta(external_account_required=True),
        }).to_json()

        client = self._init()

        self.assertTrue(client.external_account_required())

    # newNonce present means it will pick acme_version 2
    def test_external_account_required_false(self):
        self.response.json.return_value = messages.Directory({
            'newNonce': 'http://letsencrypt-test.com/acme/new-nonce',
            'meta': messages.Directory.Meta(external_account_required=False),
        }).to_json()

        client = self._init()

        self.assertFalse(client.external_account_required())

    def test_external_account_required_false_v1(self):
        self.response.json.return_value = messages.Directory({
            'meta': messages.Directory.Meta(external_account_required=False),
        }).to_json()

        client = self._init()

        self.assertFalse(client.external_account_required())


class ClientTest(ClientTestBase):
    """Tests for acme.client.Client."""

    def setUp(self):
        super().setUp()

        self.directory = DIRECTORY_V1

        # Registration
        self.regr = self.regr.update(
            terms_of_service='https://www.letsencrypt-demo.org/tos')

        # Request issuance
        self.certr = messages.CertificateResource(
            body=messages_test.CERT, authzrs=(self.authzr,),
            uri='https://www.letsencrypt-demo.org/acme/cert/1',
            cert_chain_uri='https://www.letsencrypt-demo.org/ca')

        from acme.client import Client
        self.client = Client(
            directory=self.directory, key=KEY, alg=jose.RS256, net=self.net)

    def test_init_downloads_directory(self):
        uri = 'http://www.letsencrypt-demo.org/directory'
        from acme.client import Client
        self.client = Client(
            directory=uri, key=KEY, alg=jose.RS256, net=self.net)
        self.net.get.assert_called_once_with(uri)

    @mock.patch('acme.client.ClientNetwork')
    def test_init_without_net(self, mock_net):
        mock_net.return_value = mock.sentinel.net
        alg = jose.RS256
        from acme.client import Client
        self.client = Client(
            directory=self.directory, key=KEY, alg=alg)
        mock_net.called_once_with(KEY, alg=alg, verify_ssl=True)
        self.assertEqual(self.client.net, mock.sentinel.net)

    def test_register(self):
        # "Instance of 'Field' has no to_json/update member" bug:
        self.response.status_code = http_client.CREATED
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers['Location'] = self.regr.uri
        self.response.links.update({
            'terms-of-service': {'url': self.regr.terms_of_service},
        })

        self.assertEqual(self.regr, self.client.register(self.new_reg))
        # TODO: test POST call arguments

    def test_update_registration(self):
        # "Instance of 'Field' has no to_json/update member" bug:
        self.response.headers['Location'] = self.regr.uri
        self.response.json.return_value = self.regr.body.to_json()
        self.assertEqual(self.regr, self.client.update_registration(self.regr))
        # TODO: test POST call arguments

        # TODO: split here and separate test
        self.response.json.return_value = self.regr.body.update(
            contact=()).to_json()

    def test_deactivate_account(self):
        self.response.headers['Location'] = self.regr.uri
        self.response.json.return_value = self.regr.body.to_json()
        self.assertEqual(self.regr,
                         self.client.deactivate_registration(self.regr))

    def test_query_registration(self):
        self.response.json.return_value = self.regr.body.to_json()
        self.assertEqual(self.regr, self.client.query_registration(self.regr))

    def test_agree_to_tos(self):
        self.client.update_registration = mock.Mock()
        self.client.agree_to_tos(self.regr)
        regr = self.client.update_registration.call_args[0][0]
        self.assertEqual(self.regr.terms_of_service, regr.body.agreement)

    def _prepare_response_for_request_challenges(self):
        self.response.status_code = http_client.CREATED
        self.response.headers['Location'] = self.authzr.uri
        self.response.json.return_value = self.authz.to_json()

    def test_request_challenges(self):
        self._prepare_response_for_request_challenges()
        self.client.request_challenges(self.identifier)
        self.net.post.assert_called_once_with(
            self.directory.new_authz,
            messages.NewAuthorization(identifier=self.identifier),
            acme_version=1)

    def test_request_challenges_deprecated_arg(self):
        self._prepare_response_for_request_challenges()
        self.client.request_challenges(self.identifier, new_authzr_uri="hi")
        self.net.post.assert_called_once_with(
            self.directory.new_authz,
            messages.NewAuthorization(identifier=self.identifier),
            acme_version=1)

    def test_request_challenges_custom_uri(self):
        self._prepare_response_for_request_challenges()
        self.client.request_challenges(self.identifier)
        self.net.post.assert_called_once_with(
            'https://www.letsencrypt-demo.org/acme/new-authz', mock.ANY,
            acme_version=1)

    def test_request_challenges_unexpected_update(self):
        self._prepare_response_for_request_challenges()
        self.response.json.return_value = self.authz.update(
            identifier=self.identifier.update(value='foo')).to_json()
        self.assertRaises(
            errors.UnexpectedUpdate, self.client.request_challenges,
            self.identifier)

    def test_request_challenges_wildcard(self):
        wildcard_identifier = messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value='*.example.org')
        self.assertRaises(
            errors.WildcardUnsupportedError, self.client.request_challenges,
            wildcard_identifier)

    def test_request_domain_challenges(self):
        self.client.request_challenges = mock.MagicMock()
        self.assertEqual(
            self.client.request_challenges(self.identifier),
            self.client.request_domain_challenges('example.com'))

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
        self.assertIs(cert[0], csr)
        self.assertIs(cert[1], updated_authzrs)
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

        # exceeded max_attempts | TODO: move to a separate test
        self.assertRaises(
            errors.PollError, self.client.poll_and_request_issuance,
            csr, authzrs, mintime=mintime, max_attempts=2)

    def test_deactivate_authorization(self):
        authzb = self.authzr.body.update(status=messages.STATUS_DEACTIVATED)
        self.response.json.return_value = authzb.to_json()
        authzr = self.client.deactivate_authorization(self.authzr)
        self.assertEqual(authzb, authzr.body)
        self.assertEqual(self.client.net.post.call_count, 1)
        self.assertIn(self.authzr.uri, self.net.post.call_args_list[0][0])

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
        self.client.revoke(self.certr.body, self.rsn)
        self.net.post.assert_called_once_with(
            self.directory[messages.Revocation], mock.ANY, acme_version=1)

    def test_revocation_payload(self):
        obj = messages.Revocation(certificate=self.certr.body, reason=self.rsn)
        self.assertIn('reason', obj.to_partial_json().keys())
        self.assertEqual(self.rsn, obj.to_partial_json()['reason'])

    def test_revoke_bad_status_raises_error(self):
        self.response.status_code = http_client.METHOD_NOT_ALLOWED
        self.assertRaises(
            errors.ClientError,
            self.client.revoke,
            self.certr,
            self.rsn)


class ClientV2Test(ClientTestBase):
    """Tests for acme.client.ClientV2."""

    def setUp(self):
        super().setUp()

        self.directory = DIRECTORY_V2

        from acme.client import ClientV2
        self.client = ClientV2(self.directory, self.net)

        self.new_reg = self.new_reg.update(terms_of_service_agreed=True)

        self.authzr_uri2 = 'https://www.letsencrypt-demo.org/acme/authz/2'
        self.authz2 = self.authz.update(identifier=messages.Identifier(
            typ=messages.IDENTIFIER_FQDN, value='www.example.com'),
            status=messages.STATUS_PENDING)
        self.authzr2 = messages.AuthorizationResource(
            body=self.authz2, uri=self.authzr_uri2)

        self.order = messages.Order(
            identifiers=(self.authz.identifier, self.authz2.identifier),
            status=messages.STATUS_PENDING,
            authorizations=(self.authzr.uri, self.authzr_uri2),
            finalize='https://www.letsencrypt-demo.org/acme/acct/1/order/1/finalize')
        self.orderr = messages.OrderResource(
            body=self.order,
            uri='https://www.letsencrypt-demo.org/acme/acct/1/order/1',
            authorizations=[self.authzr, self.authzr2], csr_pem=CSR_MIXED_PEM)

    def test_new_account(self):
        self.response.status_code = http_client.CREATED
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers['Location'] = self.regr.uri

        self.assertEqual(self.regr, self.client.new_account(self.new_reg))

    def test_new_account_conflict(self):
        self.response.status_code = http_client.OK
        self.response.headers['Location'] = self.regr.uri
        self.assertRaises(errors.ConflictError, self.client.new_account, self.new_reg)

    def test_new_order(self):
        order_response = copy.deepcopy(self.response)
        order_response.status_code = http_client.CREATED
        order_response.json.return_value = self.order.to_json()
        order_response.headers['Location'] = self.orderr.uri
        self.net.post.return_value = order_response

        authz_response = copy.deepcopy(self.response)
        authz_response.json.return_value = self.authz.to_json()
        authz_response.headers['Location'] = self.authzr.uri
        authz_response2 = self.response
        authz_response2.json.return_value = self.authz2.to_json()
        authz_response2.headers['Location'] = self.authzr2.uri

        with mock.patch('acme.client.ClientV2._post_as_get') as mock_post_as_get:
            mock_post_as_get.side_effect = (authz_response, authz_response2)
            self.assertEqual(self.client.new_order(CSR_MIXED_PEM), self.orderr)

    @mock.patch('acme.client.datetime')
    def test_poll_and_finalize(self, mock_datetime):
        mock_datetime.datetime.now.return_value = datetime.datetime(2018, 2, 15)
        mock_datetime.timedelta = datetime.timedelta
        expected_deadline = mock_datetime.datetime.now() + datetime.timedelta(seconds=90)

        self.client.poll_authorizations = mock.Mock(return_value=self.orderr)
        self.client.finalize_order = mock.Mock(return_value=self.orderr)

        self.assertEqual(self.client.poll_and_finalize(self.orderr), self.orderr)
        self.client.poll_authorizations.assert_called_once_with(self.orderr, expected_deadline)
        self.client.finalize_order.assert_called_once_with(self.orderr, expected_deadline)

    @mock.patch('acme.client.datetime')
    def test_poll_authorizations_timeout(self, mock_datetime):
        now_side_effect = [datetime.datetime(2018, 2, 15),
                           datetime.datetime(2018, 2, 16),
                           datetime.datetime(2018, 2, 17)]
        mock_datetime.datetime.now.side_effect = now_side_effect
        self.response.json.side_effect = [
            self.authz.to_json(), self.authz2.to_json(), self.authz2.to_json()]

        self.assertRaises(
            errors.TimeoutError, self.client.poll_authorizations, self.orderr, now_side_effect[1])

    def test_poll_authorizations_failure(self):
        deadline = datetime.datetime(9999, 9, 9)
        challb = self.challr.body.update(status=messages.STATUS_INVALID,
                                         error=messages.Error.with_code('unauthorized'))
        authz = self.authz.update(status=messages.STATUS_INVALID, challenges=(challb,))
        self.response.json.return_value = authz.to_json()

        self.assertRaises(
            errors.ValidationError, self.client.poll_authorizations, self.orderr, deadline)

    def test_poll_authorizations_success(self):
        deadline = datetime.datetime(9999, 9, 9)
        updated_authz2 = self.authz2.update(status=messages.STATUS_VALID)
        updated_authzr2 = messages.AuthorizationResource(
            body=updated_authz2, uri=self.authzr_uri2)
        updated_orderr = self.orderr.update(authorizations=[self.authzr, updated_authzr2])

        self.response.json.side_effect = (
            self.authz.to_json(), self.authz2.to_json(), updated_authz2.to_json())
        self.assertEqual(self.client.poll_authorizations(self.orderr, deadline), updated_orderr)

    def test_finalize_order_success(self):
        updated_order = self.order.update(
            certificate='https://www.letsencrypt-demo.org/acme/cert/',
            status=messages.STATUS_VALID)
        updated_orderr = self.orderr.update(body=updated_order, fullchain_pem=CERT_SAN_PEM)

        self.response.json.return_value = updated_order.to_json()
        self.response.text = CERT_SAN_PEM

        deadline = datetime.datetime(9999, 9, 9)
        self.assertEqual(self.client.finalize_order(self.orderr, deadline), updated_orderr)

    def test_finalize_order_error(self):
        updated_order = self.order.update(
            error=messages.Error.with_code('unauthorized'),
            status=messages.STATUS_INVALID)
        self.response.json.return_value = updated_order.to_json()

        deadline = datetime.datetime(9999, 9, 9)
        self.assertRaises(errors.IssuanceError, self.client.finalize_order, self.orderr, deadline)

    def test_finalize_order_invalid_status(self):
        # https://github.com/certbot/certbot/issues/9296
        order = self.order.update(error=None, status=messages.STATUS_INVALID)
        self.response.json.return_value = order.to_json()
        with self.assertRaises(errors.Error) as error:
            self.client.finalize_order(self.orderr, datetime.datetime(9999, 9, 9))
        self.assertIn("The certificate order failed", str(error.exception))

    def test_finalize_order_timeout(self):
        deadline = datetime.datetime.now() - datetime.timedelta(seconds=60)
        self.assertRaises(errors.TimeoutError, self.client.finalize_order, self.orderr, deadline)

    @mock.patch('acme.client.datetime')
    @mock.patch('acme.client.ClientV2.retry_after')
    def test_determine_sleep_seconds(self, retry_after_mock, dt_mock):
        self.response.headers['Retry-After'] = 'Tue, 19 Apr 2022 09:00:10 GMT'
        retry_after_mock.return_value = datetime.datetime(2022, 4, 19, 9, 0, 10)

        # now < deadline < retry_after -> sleep until deadline
        deadline1 = datetime.datetime(2022, 4, 19, 9, 0, 5)
        dt_mock.datetime.now.return_value = datetime.datetime(2022, 4, 19, 9, 0, 0)
        self.assertEqual(5,
                         self.client._determine_sleep_seconds(self.response,
                                                              deadline1))

        # retry_after < now < deadline -> sleep default seconds
        deadline2 = datetime.datetime(2022, 4, 19, 9, 10, 5)
        dt_mock.datetime.now.return_value = datetime.datetime(2022, 4, 19, 9, 10, 0)
        self.assertEqual(3,
                         self.client._determine_sleep_seconds(self.response,
                                                              deadline2,
                                                              3))

        # now < retry_after < deadline -> sleep until retry_after
        deadline3 = datetime.datetime(2022, 4, 19, 9, 15, 0)
        dt_mock.datetime.now.return_value = datetime.datetime(2022, 4, 19, 8, 55, 0)
        self.assertEqual(310,
                         self.client._determine_sleep_seconds(self.response,
                                                              deadline3))

        # deadline < now -> sleep default seconds
        deadline4 = datetime.datetime(2022, 4, 19, 9, 0, 11)
        dt_mock.datetime.now.return_value = datetime.datetime(2022, 4, 19, 9, 0, 12)
        self.assertEqual(2,
                         self.client._determine_sleep_seconds(self.response,
                                                              deadline4,
                                                              2))

    def test_finalize_order_alt_chains(self):
        updated_order = self.order.update(
            certificate='https://www.letsencrypt-demo.org/acme/cert/',
            status=messages.STATUS_VALID
        )
        updated_orderr = self.orderr.update(body=updated_order,
                                            fullchain_pem=CERT_SAN_PEM,
                                            alternative_fullchains_pem=[CERT_SAN_PEM,
                                                                        CERT_SAN_PEM])
        self.response.json.return_value = updated_order.to_json()
        self.response.text = CERT_SAN_PEM
        self.response.headers['Link'] ='<https://example.com/acme/cert/1>;rel="alternate", ' + \
            '<https://example.com/dir>;rel="index", ' + \
            '<https://example.com/acme/cert/2>;title="foo";rel="alternate"'

        deadline = datetime.datetime(9999, 9, 9)
        resp = self.client.finalize_order(self.orderr, deadline, fetch_alternative_chains=True)
        self.net.post.assert_any_call('https://example.com/acme/cert/1',
                                      mock.ANY, acme_version=2, new_nonce_url=mock.ANY)
        self.net.post.assert_any_call('https://example.com/acme/cert/2',
                                      mock.ANY, acme_version=2, new_nonce_url=mock.ANY)
        self.assertEqual(resp, updated_orderr)

        del self.response.headers['Link']
        resp = self.client.finalize_order(self.orderr, deadline, fetch_alternative_chains=True)
        self.assertEqual(resp, updated_orderr.update(alternative_fullchains_pem=[]))

    def test_revoke(self):
        self.client.revoke(messages_test.CERT, self.rsn)
        self.net.post.assert_called_once_with(
            self.directory["revokeCert"], mock.ANY, acme_version=2,
            new_nonce_url=DIRECTORY_V2['newNonce'])

    def test_update_registration(self):
        # "Instance of 'Field' has no to_json/update member" bug:
        self.response.headers['Location'] = self.regr.uri
        self.response.json.return_value = self.regr.body.to_json()
        self.assertEqual(self.regr, self.client.update_registration(self.regr))
        self.assertIsNotNone(self.client.net.account)
        self.assertEqual(self.client.net.post.call_count, 2)
        self.assertIn(DIRECTORY_V2.newAccount, self.net.post.call_args_list[0][0])

        self.response.json.return_value = self.regr.body.update(
            contact=()).to_json()

    def test_external_account_required_true(self):
        self.client.directory = messages.Directory({
            'meta': messages.Directory.Meta(external_account_required=True)
        })

        self.assertTrue(self.client.external_account_required())

    def test_external_account_required_false(self):
        self.client.directory = messages.Directory({
            'meta': messages.Directory.Meta(external_account_required=False)
        })

        self.assertFalse(self.client.external_account_required())

    def test_external_account_required_default(self):
        self.assertFalse(self.client.external_account_required())

    def test_post_as_get(self):
        with mock.patch('acme.client.ClientV2._authzr_from_response') as mock_client:
            mock_client.return_value = self.authzr2

            self.client.poll(self.authzr2)  # pylint: disable=protected-access

            self.client.net.post.assert_called_once_with(
                self.authzr2.uri, None, acme_version=2,
                new_nonce_url='https://www.letsencrypt-demo.org/acme/new-nonce')
            self.client.net.get.assert_not_called()


class MockJSONDeSerializable(VersionedLEACMEMixin, jose.JSONDeSerializable):
    # pylint: disable=missing-docstring
    def __init__(self, value):
        self.value = value

    def to_partial_json(self):
        return {'foo': self.value}

    @classmethod
    def from_json(cls, jobj):
        pass  # pragma: no cover


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
        self.assertIs(self.net.verify_ssl, self.verify_ssl)

    def test_wrap_in_jws(self):
        # pylint: disable=protected-access
        jws_dump = self.net._wrap_in_jws(
            MockJSONDeSerializable('foo'), nonce=b'Tg', url="url",
            acme_version=1)
        jws = acme_jws.JWS.json_loads(jws_dump)
        self.assertEqual(json.loads(jws.payload.decode()), {'foo': 'foo'})
        self.assertEqual(jws.signature.combined.nonce, b'Tg')

    def test_wrap_in_jws_v2(self):
        self.net.account = {'uri': 'acct-uri'}
        # pylint: disable=protected-access
        jws_dump = self.net._wrap_in_jws(
            MockJSONDeSerializable('foo'), nonce=b'Tg', url="url",
            acme_version=2)
        jws = acme_jws.JWS.json_loads(jws_dump)
        self.assertEqual(json.loads(jws.payload.decode()), {'foo': 'foo'})
        self.assertEqual(jws.signature.combined.nonce, b'Tg')
        self.assertEqual(jws.signature.combined.kid, u'acct-uri')
        self.assertEqual(jws.signature.combined.url, u'url')

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
        self.response.json.return_value = messages.Error.with_code(
            'serverInternal', detail='foo', title='some title').to_json()
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
            self.assertEqual(
                self.response, self.net._check_response(self.response))

    @mock.patch('acme.client.logger')
    def test_check_response_ok_ct_with_charset(self, mock_logger):
        self.response.json.return_value = {}
        self.response.headers['Content-Type'] = 'application/json; charset=utf-8'
        # pylint: disable=protected-access
        self.assertEqual(self.response, self.net._check_response(
            self.response, content_type='application/json'))
        try:
            mock_logger.debug.assert_called_with(
                'Ignoring wrong Content-Type (%r) for JSON decodable response',
                'application/json; charset=utf-8'
            )
        except AssertionError:
            return
        raise AssertionError('Expected Content-Type warning ' #pragma: no cover
            'to not have been logged')

    @mock.patch('acme.client.logger')
    def test_check_response_ok_bad_ct(self, mock_logger):
        self.response.json.return_value = {}
        self.response.headers['Content-Type'] = 'text/plain'
        # pylint: disable=protected-access
        self.assertEqual(self.response, self.net._check_response(
            self.response, content_type='application/json'))
        mock_logger.debug.assert_called_with(
            'Ignoring wrong Content-Type (%r) for JSON decodable response',
            'text/plain'
        )

    def test_check_response_conflict(self):
        self.response.ok = False
        self.response.status_code = 409
        # pylint: disable=protected-access
        self.assertRaises(errors.ConflictError, self.net._check_response, self.response)

    def test_check_response_jobj(self):
        self.response.json.return_value = {}
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access
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
            headers=mock.ANY, verify=mock.ANY, timeout=mock.ANY, bar='baz')

    @mock.patch('acme.client.logger')
    def test_send_request_get_der(self, mock_logger):
        self.net.session = mock.MagicMock()
        self.net.session.request.return_value = mock.MagicMock(
            ok=True, status_code=http_client.OK,
            headers={"Content-Type": "application/pkix-cert"},
            content=b"hi")
        # pylint: disable=protected-access
        self.net._send_request('HEAD', 'http://example.com/', 'foo',
          timeout=mock.ANY, bar='baz')
        mock_logger.debug.assert_called_with(
            'Received response:\nHTTP %d\n%s\n\n%s', 200,
            'Content-Type: application/pkix-cert', b'aGk=')

    def test_send_request_post(self):
        self.net.session = mock.MagicMock()
        self.net.session.request.return_value = self.response
        # pylint: disable=protected-access
        self.assertEqual(self.response, self.net._send_request(
            'POST', 'http://example.com/', 'foo', data='qux', bar='baz'))
        self.net.session.request.assert_called_once_with(
            'POST', 'http://example.com/', 'foo',
            headers=mock.ANY, verify=mock.ANY, timeout=mock.ANY, data='qux', bar='baz')

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
                'GET', 'http://example.com/', verify=verify,
                timeout=mock.ANY, headers=mock.ANY)

    def test_send_request_user_agent(self):
        self.net.session = mock.MagicMock()
        # pylint: disable=protected-access
        self.net._send_request('GET', 'http://example.com/',
                               headers={'bar': 'baz'})
        self.net.session.request.assert_called_once_with(
            'GET', 'http://example.com/', verify=mock.ANY,
            timeout=mock.ANY,
            headers={'User-Agent': 'acme-python-test', 'bar': 'baz'})

        self.net._send_request('GET', 'http://example.com/',
                               headers={'User-Agent': 'foo2'})
        self.net.session.request.assert_called_with(
            'GET', 'http://example.com/',
            verify=mock.ANY, timeout=mock.ANY, headers={'User-Agent': 'foo2'})

    def test_send_request_timeout(self):
        self.net.session = mock.MagicMock()
        # pylint: disable=protected-access
        self.net._send_request('GET', 'http://example.com/',
                               headers={'bar': 'baz'})
        self.net.session.request.assert_called_once_with(
            mock.ANY, mock.ANY, verify=mock.ANY, headers=mock.ANY,
            timeout=45)

    def test_del(self, close_exception=None):
        sess = mock.MagicMock()

        if close_exception is not None:
            sess.close.side_effect = close_exception

        self.net.session = sess
        del self.net
        sess.close.assert_called_once_with()

    def test_del_error(self):
        self.test_del(ReferenceError)

    @mock.patch('acme.client.requests')
    def test_requests_error_passthrough(self, mock_requests):
        mock_requests.exceptions = requests.exceptions
        mock_requests.request.side_effect = requests.exceptions.RequestException
        # pylint: disable=protected-access
        self.assertRaises(requests.exceptions.RequestException,
                          self.net._send_request, 'GET', 'uri')

    def test_urllib_error(self):
        # Using a connection error to test a properly formatted error message
        try:
            # pylint: disable=protected-access
            self.net._send_request('GET', "http://localhost:19123/nonexistent.txt")

        # Value Error Generated Exceptions
        except ValueError as y:
            self.assertEqual("Requesting localhost/nonexistent: "
                             "Connection refused", str(y))

        # Requests Library Exceptions
        except requests.exceptions.ConnectionError as z: #pragma: no cover
            self.assertTrue("'Connection aborted.'" in str(z) or "[WinError 10061]" in str(z))


class ClientNetworkWithMockedResponseTest(unittest.TestCase):
    """Tests for acme.client.ClientNetwork which mock out response."""

    def setUp(self):
        from acme.client import ClientNetwork
        self.net = ClientNetwork(key=None, alg=None)

        self.response = mock.MagicMock(ok=True, status_code=http_client.OK)
        self.response.headers = {}
        self.response.links = {}
        self.response.checked = False
        self.acmev1_nonce_response = mock.MagicMock(
            ok=False, status_code=http_client.METHOD_NOT_ALLOWED)
        self.acmev1_nonce_response.headers = {}
        self.obj = mock.MagicMock()
        self.wrapped_obj = mock.MagicMock()
        self.content_type = mock.sentinel.content_type

        self.all_nonces = [
            jose.b64encode(b'Nonce'),
            jose.b64encode(b'Nonce2'), jose.b64encode(b'Nonce3')]
        self.available_nonces = self.all_nonces[:]

        def send_request(*args, **kwargs):
            # pylint: disable=unused-argument,missing-docstring
            self.assertNotIn("new_nonce_url", kwargs)
            method = args[0]
            uri = args[1]
            if method == 'HEAD' and uri != "new_nonce_uri":
                response = self.acmev1_nonce_response
            else:
                response = self.response

            if self.available_nonces:
                response.headers = {
                    self.net.REPLAY_NONCE_HEADER:
                    self.available_nonces.pop().decode()}
            else:
                response.headers = {}
            return response

        # pylint: disable=protected-access
        self.net._send_request = self.send_request = mock.MagicMock(
            side_effect=send_request)
        self.net._check_response = self.check_response
        self.net._wrap_in_jws = mock.MagicMock(return_value=self.wrapped_obj)

    def check_response(self, response, content_type):
        # pylint: disable=missing-docstring
        self.assertEqual(self.response, response)
        self.assertEqual(self.content_type, content_type)
        self.assertTrue(self.response.ok)
        self.response.checked = True
        return self.response

    def test_head(self):
        self.assertEqual(self.acmev1_nonce_response, self.net.head(
            'http://example.com/', 'foo', bar='baz'))
        self.send_request.assert_called_once_with(
            'HEAD', 'http://example.com/', 'foo', bar='baz')

    def test_head_v2(self):
        self.assertEqual(self.response, self.net.head(
            'new_nonce_uri', 'foo', bar='baz'))
        self.send_request.assert_called_once_with(
            'HEAD', 'new_nonce_uri', 'foo', bar='baz')

    def test_get(self):
        self.assertEqual(self.response, self.net.get(
            'http://example.com/', content_type=self.content_type, bar='baz'))
        self.assertTrue(self.response.checked)
        self.send_request.assert_called_once_with(
            'GET', 'http://example.com/', bar='baz')

    def test_post_no_content_type(self):
        self.content_type = self.net.JOSE_CONTENT_TYPE
        self.assertEqual(self.response, self.net.post('uri', self.obj))
        self.assertTrue(self.response.checked)

    def test_post(self):
        # pylint: disable=protected-access
        self.assertEqual(self.response, self.net.post(
            'uri', self.obj, content_type=self.content_type))
        self.assertTrue(self.response.checked)
        self.net._wrap_in_jws.assert_called_once_with(
            self.obj, jose.b64decode(self.all_nonces.pop()), "uri", 1)

        self.available_nonces = []
        self.assertRaises(errors.MissingNonce, self.net.post,
                          'uri', self.obj, content_type=self.content_type)
        self.net._wrap_in_jws.assert_called_with(
            self.obj, jose.b64decode(self.all_nonces.pop()), "uri", 1)

    def test_post_wrong_initial_nonce(self):  # HEAD
        self.available_nonces = [b'f', jose.b64encode(b'good')]
        self.assertRaises(errors.BadNonce, self.net.post, 'uri',
                          self.obj, content_type=self.content_type)

    def test_post_wrong_post_response_nonce(self):
        self.available_nonces = [jose.b64encode(b'good'), b'f']
        self.assertRaises(errors.BadNonce, self.net.post, 'uri',
                          self.obj, content_type=self.content_type)

    def test_post_failed_retry(self):
        check_response = mock.MagicMock()
        check_response.side_effect = messages.Error.with_code('badNonce')

        # pylint: disable=protected-access
        self.net._check_response = check_response
        self.assertRaises(messages.Error, self.net.post, 'uri',
                          self.obj, content_type=self.content_type)

    def test_post_not_retried(self):
        check_response = mock.MagicMock()
        check_response.side_effect = [messages.Error.with_code('malformed'),
                                      self.response]

        # pylint: disable=protected-access
        self.net._check_response = check_response
        self.assertRaises(messages.Error, self.net.post, 'uri',
                          self.obj, content_type=self.content_type)

    def test_post_successful_retry(self):
        post_once = mock.MagicMock()
        post_once.side_effect = [messages.Error.with_code('badNonce'),
                                      self.response]

        # pylint: disable=protected-access
        self.assertEqual(self.response, self.net.post(
            'uri', self.obj, content_type=self.content_type))

    def test_head_get_post_error_passthrough(self):
        self.send_request.side_effect = requests.exceptions.RequestException
        for method in self.net.head, self.net.get:
            self.assertRaises(
                requests.exceptions.RequestException, method, 'GET', 'uri')
        self.assertRaises(requests.exceptions.RequestException,
                          self.net.post, 'uri', obj=self.obj)

    def test_post_bad_nonce_head(self):
        # pylint: disable=protected-access
        # regression test for https://github.com/certbot/certbot/issues/6092
        bad_response = mock.MagicMock(ok=False, status_code=http_client.SERVICE_UNAVAILABLE)
        self.net._send_request = mock.MagicMock()
        self.net._send_request.return_value = bad_response
        self.content_type = None
        check_response = mock.MagicMock()
        self.net._check_response = check_response
        self.assertRaises(errors.ClientError, self.net.post, 'uri',
                          self.obj, content_type=self.content_type, acme_version=2,
                          new_nonce_url='new_nonce_uri')
        self.assertEqual(check_response.call_count, 1)

    def test_new_nonce_uri_removed(self):
        self.content_type = None
        self.net.post('uri', self.obj, content_type=None,
            acme_version=2, new_nonce_url='new_nonce_uri')


class ClientNetworkSourceAddressBindingTest(unittest.TestCase):
    """Tests that if ClientNetwork has a source IP set manually, the underlying library has
    used the provided source address."""

    def setUp(self):
        self.source_address = "8.8.8.8"

    def test_source_address_set(self):
        from acme.client import ClientNetwork
        net = ClientNetwork(key=None, alg=None, source_address=self.source_address)
        for adapter in net.session.adapters.values():
            self.assertIn(self.source_address, adapter.source_address)

    def test_behavior_assumption(self):
        """This is a test that guardrails the HTTPAdapter behavior so that if the default for
        a Session() changes, the assumptions here aren't violated silently."""
        from acme.client import ClientNetwork
        # Source address not specified, so the default adapter type should be bound -- this
        # test should fail if the default adapter type is changed by requests
        net = ClientNetwork(key=None, alg=None)
        session = requests.Session()
        for scheme in session.adapters:
            client_network_adapter = net.session.adapters.get(scheme)
            default_adapter = session.adapters.get(scheme)
            self.assertEqual(client_network_adapter.__class__, default_adapter.__class__)

if __name__ == '__main__':
    unittest.main()  # pragma: no cover
