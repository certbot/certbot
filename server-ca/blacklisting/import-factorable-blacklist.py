#!/usr/bin/env python

# This imports the factorable moduli blacklist file into the
# Redis set "factorable_moduli".  Specify one or more files on the
# command line to import them.

# E.g.,
# python import-openssl-blacklist.py factorable_moduli.txt
# will import everything.  This assumes that the input moduli are
# already hexadecimal.  This script converts the moduli into the Debian
# blacklist format before inserting them into Redis.

import sys, redis, hashlib

r = redis.Redis()

for f in sys.argv[1:]:
    for line in list(open(f)):
        m = line.upper().strip()
        m2 = m.lstrip("0")   # version without leading zeroes
        h1 = hashlib.sha1("Modulus=%s\n" % m).hexdigest()[20:]
        h2 = hashlib.sha1("Modulus=%s\n" % m2).hexdigest()[20:]
        r.sadd("factorable_moduli", h1)
        r.sadd("factorable_moduli", h2)
