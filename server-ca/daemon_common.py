#!/usr/bin/env python

# functions common to the various kinds of daemon

import time, binascii
from Crypto import Random

import redis
log_redis = redis.Redis()

def signal_handler(a, b):
    global clean_shutdown
    clean_shutdown = True
    r.publish("exit", "clean-exit")
    r.lpush("exit", "clean-exit")

def short(session):
    """Return the first 12 bytes of a session ID, or, for a
    challenge ID, the challenge ID with the session ID truncated."""
    tmp = session.partition(":")
    return tmp[0][:12] + "..." + tmp[1] + tmp[2]

def random():
    """Return 64 hex digits representing a new 32-byte random number."""
    return binascii.hexlify(Random.get_random_bytes(32))

def random_raw():
    """Return 32 random bytes."""
    return Random.get_random_bytes(32)

def log(msg, session = None):
    if session:
        log_redis.publish("logs", "%s: %s" % (short(session), msg))
    else:
        log_redis.publish("logs", "%s" % session)
