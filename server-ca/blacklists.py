#!/usr/bin/env python

import redis

r = redis.Redis()

# Moduli should be stored in Redis in hexadecimal, all uppercase.  If these
# sets don't exist, sismember returns False (not an exception).

class forbidden_moduli(object):
    def __contains__(self, modulus):
        return r.sismember("debian_moduli", modulus) or r.sismember("factorable_moduli", modulus)

class forbidden_names(object):
    def __contains__(self, name):
        return r.sismember("forbidden_names", name)
