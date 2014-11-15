#!/usr/bin/env python

# This imports a Debian OpenSSL modulus blacklist file into the
# Redis set "debian_moduli".  Specify one or more files on the
# command line to import them.  Importing will require somewhere
# around a minute per file.

# E.g.,
# python import-openssl-blacklist.py /usr/share/openssl-blacklist/blacklist.*
# will import everything (including 1024 and 512 bit moduli, which might be
# rejected for other reasons).

# It would probably be a lot faster to make this use
# http://redis.io/topics/mass-insert
# instead of the Python redis library, or, indeed, to simply use
# grep -hv '#' /usr/share/openssl-blacklist/blacklist.RSA-* | sed 's/^/sadd debian_moduli /' | redis-cli --pipe
# but this requires redis-cli 2.4, and our test systems all have only
# redis-cli 2.2.12.

import sys, redis

r = redis.Redis()

for f in sys.argv[1:]:
    for line in open(f):
        if "#" not in line and len(line.rstrip()) == 20:
            r.sadd("debian_moduli", line.rstrip())
