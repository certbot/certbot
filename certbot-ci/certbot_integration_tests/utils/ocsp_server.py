import datetime
import sys
from dateutil import parser

import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509 import ocsp
from six.moves import BaseHTTPServer

from certbot_integration_tests.utils.misc import GracefulTCPServer
from certbot_integration_tests.utils.constants import MOCK_OCSP_SERVER_PORT, PEBBLE_MANAGEMENT_URL


def _create_ocsp_handler():
    class ProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_POST(self):
            request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediate-key', verify=False)
            issuer_key = serialization.load_pem_private_key(request.content, None, default_backend())

            request = requests.get(PEBBLE_MANAGEMENT_URL + '/intermediate', verify=False)
            issuer_cert = x509.load_pem_x509_certificate(request.content, default_backend())

            try:
                content_len = int(self.headers.getheader('content-length', 0))
            except AttributeError:
                content_len = int(self.headers.get('Content-Length'))

            cert = x509.load_pem_x509_certificate(self.rfile.read(content_len), default_backend())
            request = requests.get('{0}/cert-status-by-serial/{1}'.format(
                PEBBLE_MANAGEMENT_URL, str(hex(cert.serial_number)).replace('0x', '')), verify=False)
            data = request.json()

            ocsp_status = getattr(ocsp.OCSPCertStatus, data['Status'].upper())

            now = datetime.datetime.utcnow()
            revocation_time = parser.parse(data['RevokedAt']) if ocsp_status == ocsp.OCSPCertStatus.REVOKED else None
            revocation_reason = x509.ReasonFlags.unspecified if ocsp_status == ocsp.OCSPCertStatus.REVOKED else None

            builder = ocsp.OCSPResponseBuilder()
            builder = builder.add_response(
                cert=cert, issuer=issuer_cert, algorithm=hashes.SHA1(),
                cert_status=ocsp_status,
                this_update=now,
                next_update=now + datetime.timedelta(hours=1),
                revocation_time=revocation_time, revocation_reason=revocation_reason
            ).responder_id(ocsp.OCSPResponderEncoding.NAME, issuer_cert)

            response = builder.sign(issuer_key, hashes.SHA256())

            self.send_response(200)
            self.end_headers()
            self.wfile.write(response.public_bytes(serialization.Encoding.DER))

    return ProxyHandler


if __name__ == '__main__':
    httpd = GracefulTCPServer(('', MOCK_OCSP_SERVER_PORT), _create_ocsp_handler())
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
