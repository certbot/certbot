#!/usr/bin/env python
"""
This runnable module interfaces itself with the Pebble management interface in order
to serve a mock OCSP responder during integration tests against Pebble.
"""
import datetime
import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp
from dateutil import parser
import requests
from six.moves import BaseHTTPServer

from certbot_integration_tests.utils.constants import MOCK_OCSP_SERVER_PORT
from certbot_integration_tests.utils.constants import PEBBLE_MANAGEMENT_URL
from certbot_integration_tests.utils.misc import GracefulTCPServer


class _ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediate-keys/0', verify=False)
        issuer_key = serialization.load_pem_private_key(request.content, None, default_backend())

        request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediates/0', verify=False)
        issuer_cert = x509.load_pem_x509_certificate(request.content, default_backend())

        try:
            content_len = int(self.headers.getheader('content-length', 0))
        except AttributeError:
            content_len = int(self.headers.get('Content-Length'))

        ocsp_request = ocsp.load_der_ocsp_request(self.rfile.read(content_len))
        response = requests.get('{0}/cert-status-by-serial/{1}'.format(
            PEBBLE_MANAGEMENT_URL, str(hex(ocsp_request.serial_number)).replace('0x', '')), verify=False)

        if not response.ok:
            ocsp_response = ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        else:
            data = response.json()

            now = datetime.datetime.utcnow()
            cert = x509.load_pem_x509_certificate(data['Certificate'].encode(), default_backend())
            if data['Status'] != 'Revoked':
                ocsp_status, revocation_time, revocation_reason = ocsp.OCSPCertStatus.GOOD, None, None
            else:
                ocsp_status, revocation_reason = ocsp.OCSPCertStatus.REVOKED, x509.ReasonFlags.unspecified
                revoked_at = re.sub(r'( \+\d{4}).*$', r'\1', data['RevokedAt'])  # "... +0000 UTC" => "+0000"
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
