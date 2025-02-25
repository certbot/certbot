#!/usr/bin/env python
"""
This runnable module interfaces itself with the Pebble management interface in order
to serve a mock OCSP responder during integration tests against Pebble.
"""
import datetime
import http.server as BaseHTTPServer
import pytz
import re
from typing import cast
from typing import Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import ocsp
from dateutil import parser
import requests

from certbot_integration_tests.utils.constants import MOCK_OCSP_SERVER_PORT
from certbot_integration_tests.utils.constants import PEBBLE_MANAGEMENT_URL
from certbot_integration_tests.utils.misc import GracefulTCPServer


class _ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    # pylint: disable=missing-function-docstring
    def do_POST(self) -> None:
        request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediate-keys/0',
                               verify=False, timeout=10)
        issuer_key = cast(
            Union[RSAPrivateKey, EllipticCurvePrivateKey],
            serialization.load_pem_private_key(request.content, None, default_backend()))

        request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediates/0',
                               verify=False, timeout=10)
        issuer_cert = x509.load_pem_x509_certificate(request.content, default_backend())

        raw_content_len = self.headers.get('Content-Length')
        assert isinstance(raw_content_len, str)
        content_len = int(raw_content_len)

        ocsp_request = ocsp.load_der_ocsp_request(self.rfile.read(content_len))
        response = requests.get('{0}/cert-status-by-serial/{1}'.format(
            PEBBLE_MANAGEMENT_URL, str(hex(ocsp_request.serial_number)).replace('0x', '')),
            verify=False, timeout=10
        )

        if not response.ok:
            ocsp_response = ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.UNAUTHORIZED
            )
        else:
            data = response.json()

            now = datetime.datetime.now(pytz.UTC)
            cert = x509.load_pem_x509_certificate(data['Certificate'].encode(), default_backend())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san.value.get_values_for_type(x509.DNSName)
            if data['Status'] != 'Revoked' or dns_names[0].startswith('aritest.'):
                #lie aritest subdomains so we can change ari window while not triggering OCSP logic
                ocsp_status = ocsp.OCSPCertStatus.GOOD
                revocation_time = None
                revocation_reason = None
            else:
                ocsp_status = ocsp.OCSPCertStatus.REVOKED
                revocation_reason = x509.ReasonFlags.unspecified
                # "... +0000 UTC" => "+0000"
                revoked_at = re.sub(r'( \+\d{4}).*$', r'\1', data['RevokedAt'])
                revocation_time = parser.parse(revoked_at)

            ocsp_response = ocsp.OCSPResponseBuilder().add_response(
                cert=cert, issuer=issuer_cert, algorithm=hashes.SHA1(),
                cert_status=ocsp_status,
                this_update=now, next_update=now + datetime.timedelta(hours=1),
                revocation_time=revocation_time, revocation_reason=revocation_reason
            ).responder_id(
                ocsp.OCSPResponderEncoding.NAME, issuer_cert
            ).sign(issuer_key, hashes.SHA256())

        self.send_response(200)
        self.end_headers()
        self.wfile.write(ocsp_response.public_bytes(serialization.Encoding.DER))


if __name__ == '__main__':
    try:
        GracefulTCPServer(('', MOCK_OCSP_SERVER_PORT), _ProxyHandler).serve_forever()
    except KeyboardInterrupt:
        pass
