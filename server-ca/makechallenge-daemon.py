#!/usr/bin/env python

# This daemon runs on the CA side to look for requests in
# the database that are waiting for challenges to be issued.

import redis, time, sys, signal

r = redis.Redis()
ps = r.pubsub()

debug = "debug" in sys.argv
clean_shutdown = False

from daemon_common import signal_handler, short, random, random_raw, log

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def makechallenge(session):
    if r.hget(session, "live") != "True":
        # This session has died due to some other reason, like an
        # illegal request or timeout, since it entered makechallenge
        # state.  Consequently, we're not allowed to advance its
        # state any further, and it should be removed from the
        # pending-requests queue and not pushed into any other queue.
        # We don't have to remove it from pending-makechallenge
        # because the caller has already done so.
        log("removing expired session", session)
        r.lrem("pending-requests", session)
        return
    # Currently only makes challenges of type 0 (DomainValidateSNI)
    # This challenge type has three internal data parameters:
    #     dvsni:nonce,  dvsni:r,  dvsni:ext
    # This challenge type sends three data parameters to the client:
    #     nonce,  y = E(r),  ext
    #
    # Make one challenge for each name.  (This one-to-one relationship
    # is not an inherent protocol requirement!)
    names = r.lrange("%s:names" % session, 0, -1)
    log("new valid request from requesting client at %s" % r.hget(session, "client-addr"), session)
    log("for %d names: %s" % (len(names), ", ".join(names), session))
    for i, name in enumerate(names):
        challenge = "%s:%d" % (session, i)
        r.hset(challenge, "challtime", int(time.time()))
        r.hset(challenge, "type", 0)   # DomainValidateSNI
        r.hset(challenge, "name", name)
        r.hset(challenge, "satisfied", False)
        r.hset(challenge, "failed", False)
        r.hset(challenge, "dvsni:nonce", random())
        r.hset(challenge, "dvsni:r", random_raw())
        r.hset(challenge, "dvsni:ext", "1.3.3.7")
        # Keep accurate count of how many challenges exist in this session.
        r.hincrby(session, "challenges", 1)
        log("created new challenge %s" % challenge, session)
    if True:  # challenges have been created
        r.hset(session, "state", "testchallenge")
    else:
        r.lpush("pending-makechallenge", session)

while True:
    (where, what) = r.brpop(["exit", "pending-makechallenge"])
    if where == "exit":
        r.lpush("exit", "exit")
        break
    elif where == "pending-makechallenge":
        makechallenge(what)
    if clean_shutdown:
        print "makechallenge daemon exiting cleanly"
        break
