#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This script generates a simple SAN CSR to be used with Let's Encrypt
# CA. Mostly intended for "auth --csr" testing, but, since it's easily
# auditable, feel free to adjust it and use it on your production web
# server.
import os
import argparse
from OpenSSL import crypto

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    cryptography=True
except ImportError:
    cryptography=False

CWD = os.getcwd()


def generate_parser():
    one_parser = argparse.ArgumentParser(description='Generate a simple SAN CSR')
    one_parser.add_argument('domain', nargs='+', help='A FQDN to add in the CSR.')
    one_parser.add_argument('--key-path', default=os.path.join(CWD, 'key.pem'),
                            help='Path for the generated key '
                                 '(default is key.pem in current directory)')
    one_parser.add_argument('--csr-path', default=os.path.join(CWD, 'csr.der'),
                            help='Path for the generated certificate '
                                 '(default is csr.der in current directory)')
    one_parser.add_argument('--key-type', default='RSA',
                            choices=['RSA', 'ECDSA'],
                            help='Key type to use, ECDSA is supported only '
                                 'if cryptography module is available')

    return one_parser


def main(domains, key_path, csr_path, key_type):
    san = ', '.join(['DNS: {0}'.format(item) for item in domains])

    if key_type == 'RSA':
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
    elif key_type == 'ECDSA':
        if not cryptography:
            raise ValueError('Error, cryptography module is not installed,'
                             'but is required to use ECDSA')

        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        key = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=NoEncryption())
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
    else:
        raise ValueError('Invalid key type: {0}'.format(key_type))

    with open(key_path, 'wb') as file:
        file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    req = crypto.X509Req()
    san_constraint = crypto.X509Extension(b'subjectAltName', False, san.encode('utf-8'))
    req.add_extensions([san_constraint])

    req.set_pubkey(key)
    req.sign(key, 'sha256')

    with open(csr_path, 'wb') as file:
        file.write(crypto.dump_certificate_request(crypto.FILETYPE_ASN1, req))

    print('You can now run: certbot auth --csr {0}'.format(csr_path))


if __name__ == '__main__':
    parser = generate_parser()
    namespace = parser.parse_args()
    main(namespace.domain, namespace.key_path, namespace.csr_path, namespace.key_type)
