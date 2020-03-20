#!/usr/bin/env python
# Test script for OpenSSL version checking
from distutils.version import LooseVersion
import sys


def main(openssl_version, apache_version):
    conf_file_location = "/etc/letsencrypt/options-ssl-apache.conf"
    with open(conf_file_location) as f:
        contents = f.read()
    if tuple(apache_version.split(".")) < (2, 4, 11) or \
        LooseVersion(openssl_version.strip()) < LooseVersion('1.0.2l'):
        # should be old version
        # assert SSLSessionTickets not in conf file
        if "SSLSessionTickets" in contents:
            raise Exception("Apache or OpenSSL version is too old, "
                "but SSLSessionTickets is enabled.")
    else:
        # should be current version
        # assert SSLSessionTickets in conf file
        if "SSLSessionTickets" not in contents:
            raise Exception("Apache and OpenSSL versions are sufficiently new, "
                "but SSLSessionTickets is not enabled.")

if __name__ == '__main__':
    main(*sys.argv[1:])
