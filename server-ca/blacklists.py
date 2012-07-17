#!/usr/bin/env python

import redis

r = redis.Redis()

# You can test strings for membership in instances of these classes
# in order to search modulus and name blacklists kept in Redis.

# Moduli should be stored in Redis in openssl-vulnkey(1) format,
# which is the rightmost 20 characters of the SHA1 hash
# of "Modulus=%s\n" % modulus.upper().
#
# If these sets don't exist, sismember returns False (not an exception).
# Redis set membership testing is very fast.  These classes are just
# making particular Redis sets look like Python sets or dictionaries for
# membership testing purposes.

class forbidden_moduli(object):
    def __contains__(self, modulus):
        return r.sismember("debian_moduli", modulus) or r.sismember("factorable_moduli", modulus)

class forbidden_names(object):
    def __contains__(self, name):
        return r.sismember("forbidden_names", name)
