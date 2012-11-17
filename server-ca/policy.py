#!/usr/bin/env python

# This file should contain functions that set CA-side policies (that
# could change over time or differ from CA to CA) on whether individual
# aspects of a session are legitimate or appropriate.

# Functions here can access Redis if necessary to examine details of
# a session.

# Examples: session expiry times

import redis

r = redis.Redis()

def payment_required(session):
    """Does this session require a payment?"""
    # Sample policy: require a payment when total number of requested
    # subject names is greater than one.
    if r.llen("%s:names" % session) > 1:
        return True
    else:
        return False

def expire_session(session, state):
    """Should this session be expired?"""
    # Different maximum age policies apply to sessions that are waiting
    # for a payment, and, in general, to sessions at different stages
    # of their lifecycle.
    # """Given that this session is in the specified named state,
    # decide whether the daemon should forcibly expire it for being too
    # old, even if no client request has caused the serve to mark the
    # session as expired.  This is most relevant to truly abandoned
    # sessions that no client ever asks about."""
    age = int(time.time()) - int(r.hget(session, "created"))
    if state == "makechallenge" and age > 120:
        if debug: print "considered", short(session), "ancient"
        return True
    if state == "testchallenge" and age > 600:
        if debug: print "considered", short(session), "ancient"
        return True
    if state == "testpayment" and age > 5000:
        if debug: print "considered", short(session), "ancient"
        return True
    return False
