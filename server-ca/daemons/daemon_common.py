#!/usr/bin/env python

# functions common to the various kinds of daemon

# TODO: define a log function that sends a pubsub message to the
# logger daemon

import time, binascii
from Crypto import Random

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

def ancient(session, state):
    """Given that this session is in the specified named state,
    decide whether the daemon should forcibly expire it for being too
    old, even if no client request has caused the serve to mark the
    session as expired.  This is most relevant to truly abandoned
    sessions that no client ever asks about."""
    age = int(time.time()) - int(r.hget(session, "created"))
    if state == "makechallenge" and age > 120:
        if debug: print "considered", short(session), "ancient"
        return True
    if state == "testchallenge" and age > 600:
        if debug: print "considered", short(session), "ancient"
        return True
    return False

def random():
    """Return 64 hex digits representing a new 32-byte random number."""
    return binascii.hexlify(Random.get_random_bytes(32))

def random_raw():
    """Return 32 random bytes."""
    return Random.get_random_bytes(32)
