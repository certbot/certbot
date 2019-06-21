import datetime
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509 import ocsp
from flask import Flask, request

app = Flask(__name__)
app.debug = False

certificates_map = {}


@app.route('/', methods=['GET'])
def heartbeat():
    return 'Done', 200


@app.route('/', methods=['PUT'])
def register_certificate():
    config = json.loads(request.get_data())
    cert_path = config['cert_path']
    ocsp_status = config['ocsp_status']

    with open(cert_path, 'rb') as file_h3:
        cert = x509.load_pem_x509_certificate(file_h3.read(), default_backend())
    serial_number = cert.serial_number
    certificates_map[serial_number] = (cert_path, ocsp_status)

    return 'Done', 200


@app.route('/', methods=['POST'])
def status_certificate():
    raw = request.get_data()
    ocsp_request = ocsp.load_der_ocsp_request(raw)

    serial_number = ocsp_request.serial_number
    if serial_number not in certificates_map:
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED)
    else:
        config = certificates_map[serial_number]
        cert_path = config[0]
        ocsp_status = getattr(ocsp.OCSPCertStatus, config[1])

        with open(os.environ['ISSUER_CERT_PATH'], 'rb') as file_h1:
            issuer_cert = x509.load_pem_x509_certificate(file_h1.read(), default_backend())
        with open(os.environ['ISSUER_KEY_PATH'], 'rb') as file_h2:
            issuer_key = serialization.load_pem_private_key(file_h2.read(), None, default_backend())
        with open(cert_path, 'rb') as file_h3:
            cert = x509.load_pem_x509_certificate(file_h3.read(), default_backend())

        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert=cert, issuer=issuer_cert, algorithm=hashes.SHA1(),
            cert_status=ocsp_status,
            this_update=datetime.datetime.now(),
            next_update=datetime.datetime.now(),
            revocation_time=None, revocation_reason=None
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, issuer_cert)

        response = builder.sign(issuer_key, hashes.SHA256())

    return response.public_bytes(serialization.Encoding.DER), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('OCSP_PORT', 4002)))
