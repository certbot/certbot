#!/usr/bin/env python

# This daemon runs on the CA side to look for requests in
# the database that are waiting for the CA to test whether
# challenges have been met, and to perform this test.

import redis, time, sys, signal
from redis_lock import redis_lock
from sni_challenge.verify import verify_challenge

r = redis.Redis()
ps = r.pubsub()

debug = "debug" in sys.argv
clean_shutdown = False

from daemon_common import signal_handler, short, random, random_raw

def signal_handler(a, b):
    global clean_shutdown
    clean_shutdown = True
    r.publish("exit", "clean-exit")

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def testchallenge(session):
    if r.hget(session, "live") != "True":
        # This session has died due to some other reason, like an
        # illegal request or timeout, since it entered testchallenge
        # state.  Consequently, we're not allowed to advance its
        # state any further, and it should be removed from the
        # pending-requests queue and not pushed into any other queue.
        # We don't have to remove it from pending-testchallenge
        # because the caller has already done so.
        if debug: print "removing expired session", short(session)
        r.lrem("pending-requests", session)
        return
    if r.hget(session, "state") != "testchallenge":
        return
    if int(r.hincrby(session, "times-tested", 1)) > 3:
        # This session has already been unsuccessfully tested three
        # times.  Clearly, something has gone wrong or the client is
        # just trying to annoy us.  Do not allow it to be tested again.
        r.hset(session, "live", False)
        r.lrem("pending-requests", session)
        return
    all_satisfied = True
    for i, name in enumerate(r.lrange("%s:names" % session, 0, -1)):
        challenge = "%s:%d" % (session, i)
        if debug: print "testing challenge", short(challenge)
        challtime = int(r.hget(challenge, "challtime"))
        challtype = int(r.hget(challenge, "type"))
        name = r.hget(challenge, "name")
        satisfied = r.hget(challenge, "satisfied") == "True"
        failed = r.hget(challenge, "failed") == "True"
        # TODO: check whether this challenge is too old
        if not satisfied and not failed:
            # if debug: print "challenge", short(challenge), "being tested"
            if challtype == 0:  # DomainValidateSNI
                if debug: print "\tbeginning dvsni test to %s" % name
                dvsni_nonce = r.hget(challenge, "dvsni:nonce")
                dvsni_r = r.hget(challenge, "dvsni:r")
                dvsni_ext = r.hget(challenge, "dvsni:ext")
                direct_result, direct_reason = verify_challenge(name, dvsni_r, dvsni_nonce, False)
                proxy_result, proxy_reason = verify_challenge(name, dvsni_r, dvsni_nonce, True)
                if debug:
                    print "\t...direct probe: %s (%s)" % (direct_result, direct_reason)
                    print "\tTor proxy probe: %s (%s)" % (proxy_result, proxy_reason)
                if direct_result and proxy_result:
                    r.hset(challenge, "satisfied", True)
                else: 
                    all_satisfied = False
                # TODO: distinguish permanent and temporarily failures
                # can cause a permanent failure under some conditions, causing
                # the session to become dead.  TODO: need to articulate what
                # those conditions are
            else:
                # Don't know how to handle this challenge type
                all_satisfied = False
        elif not satisfied:
             if debug: print "\tchallenge was not attempted"
             all_satisfied = False
    if all_satisfied:
        # Challenges all succeeded, so we should prepare to issue
        # the requested cert.
        # TODO: double-check that there were > 0 challenges,
        # so that we don't somehow mistakenly issue a cert in
        # response to an empty list of challenges (even though
        # the daemon that put this session on the queue should
        # also have implicitly guaranteed this).
        if debug: print "\t** All challenges satisfied; request %s GRANTED" % short(session)
        r.hset(session, "state", "issue")
        r.lpush("pending-issue", session)
    else:
        # Some challenges were not verified.  In the current
        # design of this daemon, the client must contact
        # us again to request that the session be placed back
        # in pending-testchallenge!
        pass

while True:
    (where, what) = r.brpop(["exit", "pending-testchallenge"])
    if where == "exit":
        r.lpush("exit", "exit")
        break
    elif where == "pending-testchallenge":
        with redis_lock(r, "lock-" + what):
            testchallenge(what)
    if clean_shutdown:
        print "daemon exiting cleanly"
        break
