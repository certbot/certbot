"""Tests for acme.client."""
# pylint: disable=too-many-lines
import copy
import datetime
import http.client as http_client
import json
import sys
from typing import Dict
import unittest
from unittest import mock

import josepy as jose
import pytest
import requests

from acme import challenges
from acme import errors
from acme import jws as acme_jws
from acme import messages
from acme._internal.tests import messages_test
from acme._internal.tests import test_util
from acme.client import ClientNetwork
from acme.client import ClientV2

CERT_SAN_PEM = test_util.load_vector('cert-san.pem')
CSR_MIXED_PEM = test_util.load_vector('csr-mixed.pem')
CSR_NO_SANS_PEM = test_util.load_vector('csr-nosans.pem')
KEY = jose.JWKRSA.load(test_util.load_vector('rsa512_key.pem'))

DIRECTORY_V2 = messages.Directory({
    'newAccount': 'https://www.letsencrypt-demo.org/acme/new-account',
    'newNonce': 'https://www.letsencrypt-demo.org/acme/new-nonce',
    'newOrder': 'https://www.letsencrypt-demo.org/acme/new-order',
    'revokeCert': 'https://www.letsencrypt-demo.org/acme/revoke-cert',
    'meta': messages.Directory.Meta(),
})


class ClientV2Test(unittest.TestCase):
    """Tests for acme.client.ClientV2."""

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
            challenges=(challb,))
        self.authzr = messages.AuthorizationResource(
            body=self.authz, uri=authzr_uri)

        # Reason code for revocation
        self.rsn = 1

        self.directory = DIRECTORY_V2

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
        self.orderr2 = messages.OrderResource(
            body=self.order,
            uri='https://www.letsencrypt-demo.org/acme/acct/1/order/1',
            authorizations=[self.authzr, self.authzr2], csr_pem=CSR_NO_SANS_PEM)

    def test_new_account(self):
        self.response.status_code = http_client.CREATED
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers['Location'] = self.regr.uri

        assert self.regr == self.client.new_account(self.new_reg)

    def test_new_account_tos_link(self):
        self.response.status_code = http_client.CREATED
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers['Location'] = self.regr.uri
        self.response.links.update({
            'terms-of-service': {'url': 'https://www.letsencrypt-demo.org/tos'},
        })

        assert self.client.new_account(self.new_reg).terms_of_service == \
                         'https://www.letsencrypt-demo.org/tos'


    def test_new_account_conflict(self):
        self.response.status_code = http_client.OK
        self.response.headers['Location'] = self.regr.uri
        with pytest.raises(errors.ConflictError):
            self.client.new_account(self.new_reg)

    def test_deactivate_account(self):
        deactivated_regr = self.regr.update(
            body=self.regr.body.update(status='deactivated'))
        self.response.json.return_value = deactivated_regr.body.to_json()
        self.response.status_code = http_client.OK
        self.response.headers['Location'] = self.regr.uri
        assert self.client.deactivate_registration(self.regr) == deactivated_regr

    def test_deactivate_authorization(self):
        deactivated_authz = self.authzr.update(
            body=self.authzr.body.update(status=messages.STATUS_DEACTIVATED))
        self.response.json.return_value = deactivated_authz.body.to_json()
        authzr = self.client.deactivate_authorization(self.authzr)
        assert deactivated_authz.body == authzr.body
        assert self.client.net.post.call_count == 1
        assert self.authzr.uri in self.net.post.call_args_list[0][0]

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
            assert self.client.new_order(CSR_MIXED_PEM) == self.orderr

        with mock.patch('acme.client.ClientV2._post_as_get') as mock_post_as_get:
            mock_post_as_get.side_effect = (authz_response, authz_response2)
            assert self.client.new_order(CSR_NO_SANS_PEM) == self.orderr2

    def test_answer_challege(self):
        self.response.links['up'] = {'url': self.challr.authzr_uri}
        self.response.json.return_value = self.challr.body.to_json()
        chall_response = challenges.DNSResponse(validation=None)
        self.client.answer_challenge(self.challr.body, chall_response)

        with pytest.raises(errors.UnexpectedUpdate):
            self.client.answer_challenge(self.challr.body.update(uri='foo'), chall_response)

    def test_answer_challenge_missing_next(self):
        with pytest.raises(errors.ClientError):
            self.client.answer_challenge(self.challr.body, challenges.DNSResponse(validation=None))

    @mock.patch('acme.client.datetime')
    def test_poll_and_finalize(self, mock_datetime):
        mock_datetime.datetime.now.return_value = datetime.datetime(2018, 2, 15)
        mock_datetime.timedelta = datetime.timedelta
        expected_deadline = mock_datetime.datetime.now() + datetime.timedelta(seconds=90)

        self.client.poll_authorizations = mock.Mock(return_value=self.orderr)
        self.client.finalize_order = mock.Mock(return_value=self.orderr)

        assert self.client.poll_and_finalize(self.orderr) == self.orderr
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

        with pytest.raises(errors.TimeoutError):
            self.client.poll_authorizations(self.orderr, now_side_effect[1])

    def test_poll_authorizations_failure(self):
        deadline = datetime.datetime(9999, 9, 9)
        challb = self.challr.body.update(status=messages.STATUS_INVALID,
                                         error=messages.Error.with_code('unauthorized'))
        authz = self.authz.update(status=messages.STATUS_INVALID, challenges=(challb,))
        self.response.json.return_value = authz.to_json()

        with pytest.raises(errors.ValidationError):
            self.client.poll_authorizations(self.orderr, deadline)

    def test_poll_authorizations_success(self):
        deadline = datetime.datetime(9999, 9, 9)
        updated_authz2 = self.authz2.update(status=messages.STATUS_VALID)
        updated_authzr2 = messages.AuthorizationResource(
            body=updated_authz2, uri=self.authzr_uri2)
        updated_orderr = self.orderr.update(authorizations=[self.authzr, updated_authzr2])

        self.response.json.side_effect = (
            self.authz.to_json(), self.authz2.to_json(), updated_authz2.to_json())
        assert self.client.poll_authorizations(self.orderr, deadline) == updated_orderr

    def test_poll_unexpected_update(self):
        updated_authz = self.authz.update(identifier=self.identifier.update(value='foo'))
        self.response.json.return_value = updated_authz.to_json()
        with pytest.raises(errors.UnexpectedUpdate):
            self.client.poll(self.authzr)

    def test_finalize_order_success(self):
        updated_order = self.order.update(
            certificate='https://www.letsencrypt-demo.org/acme/cert/',
            status=messages.STATUS_VALID)
        updated_orderr = self.orderr.update(body=updated_order, fullchain_pem=CERT_SAN_PEM)

        self.response.json.return_value = updated_order.to_json()
        self.response.text = CERT_SAN_PEM

        deadline = datetime.datetime(9999, 9, 9)
        assert self.client.finalize_order(self.orderr, deadline) == updated_orderr

    def test_finalize_order_error(self):
        updated_order = self.order.update(
            error=messages.Error.with_code('unauthorized'),
            status=messages.STATUS_INVALID)
        self.response.json.return_value = updated_order.to_json()

        deadline = datetime.datetime(9999, 9, 9)
        with pytest.raises(errors.IssuanceError):
            self.client.finalize_order(self.orderr, deadline)

    def test_finalize_order_invalid_status(self):
        # https://github.com/certbot/certbot/issues/9296
        order = self.order.update(error=None, status=messages.STATUS_INVALID)
        self.response.json.return_value = order.to_json()
        with pytest.raises(errors.Error, match="The certificate order failed"):
            self.client.finalize_order(self.orderr, datetime.datetime(9999, 9, 9))

    def test_finalize_order_timeout(self):
        deadline = datetime.datetime.now() - datetime.timedelta(seconds=60)
        with pytest.raises(errors.TimeoutError):
            self.client.finalize_order(self.orderr, deadline)

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
                                      mock.ANY, new_nonce_url=mock.ANY)
        self.net.post.assert_any_call('https://example.com/acme/cert/2',
                                      mock.ANY, new_nonce_url=mock.ANY)
        assert resp == updated_orderr

        del self.response.headers['Link']
        resp = self.client.finalize_order(self.orderr, deadline, fetch_alternative_chains=True)
        assert resp == updated_orderr.update(alternative_fullchains_pem=[])

    def test_revoke(self):
        self.client.revoke(messages_test.CERT, self.rsn)
        self.net.post.assert_called_once_with(
            self.directory["revokeCert"], mock.ANY, new_nonce_url=DIRECTORY_V2['newNonce'])

    def test_revoke_bad_status_raises_error(self):
        self.response.status_code = http_client.METHOD_NOT_ALLOWED
        with pytest.raises(errors.ClientError):
            self.client.revoke(messages_test.CERT,
            self.rsn)

    def test_update_registration(self):
        # "Instance of 'Field' has no to_json/update member" bug:
        self.response.headers['Location'] = self.regr.uri
        self.response.json.return_value = self.regr.body.to_json()
        assert self.regr == self.client.update_registration(self.regr)
        assert self.client.net.account is not None
        assert self.client.net.post.call_count == 2
        assert DIRECTORY_V2.newAccount in self.net.post.call_args_list[0][0]

        self.response.json.return_value = self.regr.body.update(
            contact=()).to_json()

    def test_external_account_required_true(self):
        self.client.directory = messages.Directory({
            'meta': messages.Directory.Meta(external_account_required=True)
        })

        assert self.client.external_account_required()

    def test_external_account_required_false(self):
        self.client.directory = messages.Directory({
            'meta': messages.Directory.Meta(external_account_required=False)
        })

        assert not self.client.external_account_required()

    def test_external_account_required_default(self):
        assert not self.client.external_account_required()

    def test_query_registration_client(self):
        self.response.json.return_value = self.regr.body.to_json()
        self.response.headers['Location'] = 'https://www.letsencrypt-demo.org/acme/reg/1'
        assert self.regr == self.client.query_registration(self.regr)

    def test_post_as_get(self):
        with mock.patch('acme.client.ClientV2._authzr_from_response') as mock_client:
            mock_client.return_value = self.authzr2

            self.client.poll(self.authzr2)  # pylint: disable=protected-access

            self.client.net.post.assert_called_once_with(
                self.authzr2.uri, None,
                new_nonce_url='https://www.letsencrypt-demo.org/acme/new-nonce')
            self.client.net.get.assert_not_called()

    def test_retry_after_date(self):
        self.response.headers['Retry-After'] = 'Fri, 31 Dec 1999 23:59:59 GMT'
        assert datetime.datetime(1999, 12, 31, 23, 59, 59) == \
            self.client.retry_after(response=self.response, default=10)

    @mock.patch('acme.client.datetime')
    def test_retry_after_invalid(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.response.headers['Retry-After'] = 'foooo'
        assert datetime.datetime(2015, 3, 27, 0, 0, 10) == \
            self.client.retry_after(response=self.response, default=10)

    @mock.patch('acme.client.datetime')
    def test_retry_after_overflow(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta
        dt_mock.datetime.side_effect = datetime.datetime

        self.response.headers['Retry-After'] = "Tue, 116 Feb 2016 11:50:00 MST"
        assert datetime.datetime(2015, 3, 27, 0, 0, 10) == \
            self.client.retry_after(response=self.response, default=10)

    @mock.patch('acme.client.datetime')
    def test_retry_after_seconds(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        self.response.headers['Retry-After'] = '50'
        assert datetime.datetime(2015, 3, 27, 0, 0, 50) == \
            self.client.retry_after(response=self.response, default=10)

    @mock.patch('acme.client.datetime')
    def test_retry_after_missing(self, dt_mock):
        dt_mock.datetime.now.return_value = datetime.datetime(2015, 3, 27)
        dt_mock.timedelta = datetime.timedelta

        assert datetime.datetime(2015, 3, 27, 0, 0, 10) == \
            self.client.retry_after(response=self.response, default=10)

    def test_get_directory(self):
        self.response.json.return_value = DIRECTORY_V2.to_json()
        assert DIRECTORY_V2.to_partial_json() == \
            ClientV2.get_directory('https://example.com/dir', self.net).to_partial_json()

    def test_renewal_time_no_renewal_info(self):
        # A directory with no 'renewalInfo' should result in default renewal periods.
        self.client.directory =  messages.Directory({})
        cert_pem = make_cert_for_renewal(
            not_before=datetime.datetime(2025, 3, 12, 00, 00, 00),
            not_after=datetime.datetime(2025, 3, 20, 00, 00, 00),
        )
        t = self.client.renewal_time(cert_pem)
        assert t == datetime.datetime(2025, 3, 16, 00, 00, 00, tzinfo=datetime.timezone.utc)

        cert_pem = make_cert_for_renewal(
            not_before=datetime.datetime(2025, 3, 12, 00, 00, 00),
            not_after=datetime.datetime(2025, 3, 30, 00, 00, 00),
        )
        t = self.client.renewal_time(cert_pem)
        assert t == datetime.datetime(2025, 3, 24, 00, 00, 00, tzinfo=datetime.timezone.utc)

    def test_renewal_time_with_renewal_info(self):
        cert_pem = make_cert_for_renewal(
            not_before=datetime.datetime(2025, 3, 12, 00, 00, 00),
            not_after=datetime.datetime(2025, 3, 20, 00, 00, 00),
        )

        self.client.directory =  messages.Directory({
            'renewalInfo': 'https://www.letsencrypt-demo.org/acme/renewal-info',
        })

        self.response.json.return_value = {
            "suggestedWindow": {
                "start": "2025-03-14T01:01:01Z",
                "end": "2025-03-14T01:01:01Z",
            },
            "message": "Keep those certs fresh"
        }
        t = self.client.renewal_time(cert_pem)
        self.net.get.assert_called_once_with("https://www.letsencrypt-demo.org/acme/renewal-info/MTIzNA.AN3V", content_type='application/json')
        assert t == datetime.datetime(2025, 3, 14, 1, 1, 1, tzinfo=datetime.timezone.utc)

        self.net.reset_mock()

        self.response.json.return_value = {
            "suggestedWindow": {
                "start": "2025-03-16T01:01:01Z",
                "end": "2025-03-17T01:01:01Z",
            },
            "message": "Keep those certs fresh"
        }
        t = self.client.renewal_time(cert_pem)
        self.net.get.assert_called_once_with("https://www.letsencrypt-demo.org/acme/renewal-info/MTIzNA.AN3V", content_type='application/json')
        assert t >= datetime.datetime(2025, 3, 16, 1, 1, 1, tzinfo=datetime.timezone.utc)
        assert t <= datetime.datetime(2025, 3, 17, 1, 1, 1, tzinfo=datetime.timezone.utc)

def test_renewal_info_path_component():
    from cryptography import x509
    from acme.client import _renewal_info_path_component

    cert = x509.load_pem_x509_certificate(test_util.load_vector('rsa2048_cert.pem'))

    assert _renewal_info_path_component(cert) == "fL5sRirC8VS5AtOQh9DfoAzYNCI.ALVG_VbBb5U7"

    # From https://www.ietf.org/archive/id/draft-ietf-acme-ari-08.html appendix A.
    ARI_TEST_CERT = b"""
-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----
"""

    cert = x509.load_pem_x509_certificate(ARI_TEST_CERT)
    assert _renewal_info_path_component(cert) == "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"

if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover

def make_cert_for_renewal(not_before, not_after) -> bytes:
    """
    Return a PEM-encoded, self-signed certificate with the given dates.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    # AKID and serial are the inputs to constructing the renewalInfo URL
    akid = x509.AuthorityKeyIdentifier(b"1234", None, None)
    serial = 56789
    key = ec.generate_private_key(ec.SECP256R1())
    cert = x509.CertificateBuilder(
        issuer_name=x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Some Issuer")]),
        subject_name=x509.Name([]),
        public_key=key.public_key(),
        serial_number=serial,
        not_valid_before=not_before,
        not_valid_after=not_after,
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName('example.com')]),
        critical=False,
    ).add_extension(
        akid,
        critical=False,
    ).sign(
        private_key=key,
        algorithm=hashes.SHA256(),
    )
    return cert.public_bytes(serialization.Encoding.PEM)

class MockJSONDeSerializable(jose.JSONDeSerializable):
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

        self.net = ClientNetwork(
            key=KEY, alg=jose.RS256, verify_ssl=self.verify_ssl,
            user_agent='acme-python-test')

        self.response = mock.MagicMock(ok=True, status_code=http_client.OK)
        self.response.headers = {}
        self.response.links = {}

    def test_init(self):
        assert self.net.verify_ssl is self.verify_ssl

    def test_wrap_in_jws(self):
        # pylint: disable=protected-access
        jws_dump = self.net._wrap_in_jws(
            MockJSONDeSerializable('foo'), nonce=b'Tg', url="url")
        jws = acme_jws.JWS.json_loads(jws_dump)
        assert json.loads(jws.payload.decode()) == {'foo': 'foo'}
        assert jws.signature.combined.nonce == b'Tg'

    def test_wrap_in_jws_v2(self):
        self.net.account = {'uri': 'acct-uri'}
        # pylint: disable=protected-access
        jws_dump = self.net._wrap_in_jws(
            MockJSONDeSerializable('foo'), nonce=b'Tg', url="url")
        jws = acme_jws.JWS.json_loads(jws_dump)
        assert json.loads(jws.payload.decode()) == {'foo': 'foo'}
        assert jws.signature.combined.nonce == b'Tg'
        assert jws.signature.combined.kid == u'acct-uri'
        assert jws.signature.combined.url == u'url'

    def test_check_response_not_ok_jobj_no_error(self):
        self.response.ok = False
        self.response.json.return_value = {}
        with mock.patch('acme.client.messages.Error.from_json') as from_json:
            from_json.side_effect = jose.DeserializationError
            # pylint: disable=protected-access
            with pytest.raises(errors.ClientError):
                self.net._check_response(self.response)

    def test_check_response_not_ok_jobj_error(self):
        self.response.ok = False
        self.response.json.return_value = messages.Error.with_code(
            'serverInternal', detail='foo', title='some title').to_json()
        # pylint: disable=protected-access
        with pytest.raises(messages.Error):
            self.net._check_response(self.response)

    def test_check_response_not_ok_no_jobj(self):
        self.response.ok = False
        self.response.json.side_effect = ValueError
        # pylint: disable=protected-access
        with pytest.raises(errors.ClientError):
            self.net._check_response(self.response)

    def test_check_response_ok_no_jobj_ct_required(self):
        self.response.json.side_effect = ValueError
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access
            with pytest.raises(errors.ClientError):
                self.net._check_response(self.response,
                content_type=self.net.JSON_CONTENT_TYPE)

    def test_check_response_ok_no_jobj_no_ct(self):
        self.response.json.side_effect = ValueError
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access
            assert self.response == self.net._check_response(self.response)

    @mock.patch('acme.client.logger')
    def test_check_response_ok_ct_with_charset(self, mock_logger):
        self.response.json.return_value = {}
        self.response.headers['Content-Type'] = 'application/json; charset=utf-8'
        # pylint: disable=protected-access
        assert self.response == self.net._check_response(
            self.response, content_type='application/json')
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
        assert self.response == self.net._check_response(
            self.response, content_type='application/json')
        mock_logger.debug.assert_called_with(
            'Ignoring wrong Content-Type (%r) for JSON decodable response',
            'text/plain'
        )

    def test_check_response_conflict(self):
        self.response.ok = False
        self.response.status_code = 409
        # pylint: disable=protected-access
        with pytest.raises(errors.ConflictError):
            self.net._check_response(self.response)

    def test_check_response_jobj(self):
        self.response.json.return_value = {}
        for response_ct in [self.net.JSON_CONTENT_TYPE, 'foo']:
            self.response.headers['Content-Type'] = response_ct
            # pylint: disable=protected-access
            assert self.response == self.net._check_response(self.response)

    def test_send_request(self):
        self.net.session = mock.MagicMock()
        self.net.session.request.return_value = self.response
        # pylint: disable=protected-access
        assert self.response == self.net._send_request(
            'HEAD', 'http://example.com/', 'foo', bar='baz')
        self.net.session.request.assert_called_once_with(
            'HEAD', 'http://example.com/', 'foo',
            headers=mock.ANY, verify=mock.ANY, timeout=mock.ANY, bar='baz')

    @mock.patch('acme.client.logger')
    def test_send_request_get_der(self, mock_logger):
        self.net.session = mock.MagicMock()
        self.net.session.request.return_value = mock.MagicMock(
            ok=True, status_code=http_client.OK,
            content=b"hi")
        # pylint: disable=protected-access
        self.net._send_request('HEAD', 'http://example.com/', 'foo',
          timeout=mock.ANY, bar='baz', headers={'Accept': 'application/pkix-cert'})
        mock_logger.debug.assert_called_with(
            'Received response:\nHTTP %d\n%s\n\n%s', 200,
            '', b'aGk=')

    def test_send_request_post(self):
        self.net.session = mock.MagicMock()
        self.net.session.request.return_value = self.response
        # pylint: disable=protected-access
        assert self.response == self.net._send_request(
            'POST', 'http://example.com/', 'foo', data='qux', bar='baz')
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
            assert self.response == \
                self.net._send_request('GET', 'http://example.com/')
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
        with pytest.raises(requests.exceptions.RequestException):
            self.net._send_request('GET', 'uri')

    def test_urllib_error(self):
        # Using a connection error to test a properly formatted error message
        try:
            # pylint: disable=protected-access
            self.net._send_request('GET', "http://localhost:19123/nonexistent.txt")

        # Value Error Generated Exceptions
        except ValueError as y:
            assert "Requesting localhost/nonexistent: " \
                             "Connection refused" == str(y)

        # Requests Library Exceptions
        except requests.exceptions.ConnectionError as z: #pragma: no cover
            assert "'Connection aborted.'" in str(z) or "[WinError 10061]" in str(z)


class ClientNetworkWithMockedResponseTest(unittest.TestCase):
    """Tests for acme.client.ClientNetwork which mock out response."""

    def setUp(self):
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
            assert "new_nonce_url" not in kwargs
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
        assert self.response == response
        assert self.content_type == content_type
        assert self.response.ok
        self.response.checked = True
        return self.response

    def test_head(self):
        assert self.acmev1_nonce_response == self.net.head(
            'http://example.com/', 'foo', bar='baz')
        self.send_request.assert_called_once_with(
            'HEAD', 'http://example.com/', 'foo', bar='baz')

    def test_head_v2(self):
        assert self.response == self.net.head(
            'new_nonce_uri', 'foo', bar='baz')
        self.send_request.assert_called_once_with(
            'HEAD', 'new_nonce_uri', 'foo', bar='baz')

    def test_get(self):
        assert self.response == self.net.get(
            'http://example.com/', content_type=self.content_type, bar='baz')
        assert self.response.checked
        self.send_request.assert_called_once_with(
            'GET', 'http://example.com/', bar='baz')

    def test_post_no_content_type(self):
        self.content_type = self.net.JOSE_CONTENT_TYPE
        assert self.response == self.net.post('uri', self.obj)
        assert self.response.checked

    def test_post(self):
        # pylint: disable=protected-access
        assert self.response == self.net.post(
            'uri', self.obj, content_type=self.content_type)
        assert self.response.checked
        self.net._wrap_in_jws.assert_called_once_with(
            self.obj, jose.b64decode(self.all_nonces.pop()), "uri")

        self.available_nonces = []
        with pytest.raises(errors.MissingNonce):
            self.net.post('uri', self.obj, content_type=self.content_type)
        self.net._wrap_in_jws.assert_called_with(
            self.obj, jose.b64decode(self.all_nonces.pop()), "uri")

    def test_post_wrong_initial_nonce(self):  # HEAD
        self.available_nonces = [b'f', jose.b64encode(b'good')]
        with pytest.raises(errors.BadNonce):
            self.net.post('uri',
                          self.obj, content_type=self.content_type)

    def test_post_wrong_post_response_nonce(self):
        self.available_nonces = [jose.b64encode(b'good'), b'f']
        with pytest.raises(errors.BadNonce):
            self.net.post('uri',
                          self.obj, content_type=self.content_type)

    def test_post_failed_retry(self):
        check_response = mock.MagicMock()
        check_response.side_effect = messages.Error.with_code('badNonce')

        # pylint: disable=protected-access
        self.net._check_response = check_response
        with pytest.raises(messages.Error):
            self.net.post('uri',
                          self.obj, content_type=self.content_type)

    def test_post_not_retried(self):
        check_response = mock.MagicMock()
        check_response.side_effect = [messages.Error.with_code('malformed'),
                                      self.response]

        # pylint: disable=protected-access
        self.net._check_response = check_response
        with pytest.raises(messages.Error):
            self.net.post('uri',
                          self.obj, content_type=self.content_type)

    def test_post_successful_retry(self):
        post_once = mock.MagicMock()
        post_once.side_effect = [messages.Error.with_code('badNonce'),
                                      self.response]

        # pylint: disable=protected-access
        assert self.response == self.net.post(
            'uri', self.obj, content_type=self.content_type)

    def test_head_get_post_error_passthrough(self):
        self.send_request.side_effect = requests.exceptions.RequestException
        for method in self.net.head, self.net.get:
            with pytest.raises(requests.exceptions.RequestException):
                method('GET', 'uri')
        with pytest.raises(requests.exceptions.RequestException):
            self.net.post('uri', obj=self.obj)

    def test_post_bad_nonce_head(self):
        # pylint: disable=protected-access
        # regression test for https://github.com/certbot/certbot/issues/6092
        bad_response = mock.MagicMock(ok=False, status_code=http_client.SERVICE_UNAVAILABLE)
        self.net._send_request = mock.MagicMock()
        self.net._send_request.return_value = bad_response
        self.content_type = None
        check_response = mock.MagicMock()
        self.net._check_response = check_response
        with pytest.raises(errors.ClientError):
            self.net.post('uri',
                          self.obj, content_type=self.content_type,
                          new_nonce_url='new_nonce_uri')
        assert check_response.call_count == 1

    def test_new_nonce_uri_removed(self):
        self.content_type = None
        self.net.post('uri', self.obj, content_type=None, new_nonce_url='new_nonce_uri')


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
