#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This script generates a simple SAN CSR to be used with Let's Encrypt
# CA. Mostly intended for "auth --csr" testing, but, since it's easily
# auditable, feel free to adjust it and use it on your production web
# server.
import os
import argparse
from OpenSSL import crypto

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

    return one_parser


def main(domains, key_path, csr_path):
    san = ', '.join(['DNS: {0}'.format(item) for item in domains])

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    with open(key_path, 'bw') as file:
        file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    req = crypto.X509Req()
    san_constraint = crypto.X509Extension(b'subjectAltName', False, san.encode('utf-8'))
    req.add_extensions([san_constraint])

    req.set_pubkey(key)
    req.sign(key, 'sha256')

    with open(csr_path, 'bw') as file:
        file.write(crypto.dump_certificate_request(crypto.FILETYPE_ASN1, req))

    print('You can now run: certbot auth --csr {0}'.format(csr_path))


if __name__ == '__main__':
    parser = generate_parser()
    namespace = parser.parse_args()
    main(namespace.domain, namespace.key_path, namespace.csr_path)
