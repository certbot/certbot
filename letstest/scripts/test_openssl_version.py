#!/usr/bin/env python
# Test script for OpenSSL version checking
import sys

from certbot import util


def main(openssl_version, apache_version):
    if not openssl_version.strip():
        raise Exception("No OpenSSL version found.")
    if not apache_version.strip():
        raise Exception("No Apache version found.")
    conf_file_location = "/etc/letsencrypt/options-ssl-apache.conf"
    with open(conf_file_location) as f:
        contents = f.read()
    if util.parse_loose_version(apache_version.strip()) < util.parse_loose_version('2.4.11') or \
        util.parse_loose_version(openssl_version.strip()) < util.parse_loose_version('1.0.2l'):
        # should be old version
        # assert SSLSessionTickets not in conf file
        if "SSLSessionTickets" in contents:
            raise Exception("Apache or OpenSSL version is too old, "
                "but SSLSessionTickets is set.")
    else:
        # should be current version
        # assert SSLSessionTickets in conf file
        if "SSLSessionTickets" not in contents:
            raise Exception("Apache and OpenSSL versions are sufficiently new, "
                "but SSLSessionTickets is not set.")

if __name__ == '__main__':
    main(*sys.argv[1:])
