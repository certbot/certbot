#!/usr/bin/env python

# This daemon runs on the CA side to look for requests in
# the database that are waiting for actions to be taken:
# generating challenges, testing whether challenges have
# been met, and issuing certs when the challenges have been
# met.  The daemon does not communicate with the client at
# all; it just notes changes to request state in the database,
# which the server will inform the client about when the
# client subsequently checks in.

# The queue mechanism with pending-* is supposed to control
# concurrency issues properly, but this needs verification
# to ensure that there are no possible race conditions.
# Generally, the server process (as distinct from the daemon)
# is not supposed to change sessions at all once they have
# been added to a queue, except for marking them no longer
# live if the server realizes that something bad has happened
# to them.  There may be some exceptions, and they should all
# be analyzed for possible races.

# TODO: check sessions' internal evidence for consistency
# with their queue membership (in case of crashes or bugs).
# In particular, check that a session in pending-makechallenge
# does not actually contain any challenges and that a
# session in pending-issue does not actually contain an
# issued cert.
# TODO: write queue rebuilding script that uses sessions'
# internal state to decide which queue they go in (to
# run when starting daemon, in case there was a crash
# that caused a session not to be in any pending queue
# because the daemon was actively working on it during
# the crash); consider marking sessions "dirty" when
# beginning to actually modify their contents in order
# to allow dirty sessions to be deleted after a crash instead
# of placing them back on a queue.  Or, we could just
# decide that a crash invalidates each and every pending
# request, period, while still allowing clients to look
# up successfully issued certs.
# TODO: implement multithreading to allow several parallel
# worker processes.
#
# NOTE: The daemon enforces its own timeouts, which are
# defined in the ancient() function.  These timeouts apply
# to any session that has been placed in a queue and can
# be completely independent of the session timeout policy
# in the server.  Being marked as dead at any time by either
# the server or the daemon (due to timeout or error) causes
# a session to be treated as dead by both.

import redis, redis_lock, time, CSR, sys, signal, binascii
from sni_challenge.verify import verify_challenge
from Crypto import Random

r = redis.Redis()
ps = r.pubsub()
issue_lock = redis_lock.redis_lock(r, "issue_lock")
# This lock guards the ability to issue certificates with "openssl ca",
# which has no locking of its own.  We don't need locking for the updates
# that the daemon performs on the sessions in the database because the
# queues pending-makechallenge, pending-testchallenge, and pending-issue
# are updated atomically and the daemon only ever acts on sessions that it
# has removed from a queue.
# TODO: in a deployed system, the queue for issuing certs should probably
# be treated a first-come, first-issue fashion, so that a request doesn't
# time out while waiting to acquire the lock just because other requests
# happened to get it first. Another way of putting this is that there
# could be only one thread/process that deals with pending-issue sessions,
# even though there could be many that deal with pending-makechallenge and
# pending-testchallenge.  Then we can guarantee that the oldest pending-issue
# requests are dealt with first, which is impossible to guarantee when
# multiple daemons may be opportunistically acquiring this lock.

debug = "debug" in sys.argv
clean_shutdown = False

def signal_handler(a, b):
    global clean_shutdown
    clean_shutdown = True
    r.publish("exit", "clean-exit")

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

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

def makechallenge(session):
    if r.hget(session, "live") != "True":
        # This session has died due to some other reason, like an
        # illegal request or timeout, since it entered makechallenge
        # state.  Consequently, we're not allowed to advance its
        # state any further, and it should be removed from the
        # pending-requests queue and not pushed into any other queue.
        # We don't have to remove it from pending-makechallenge
        # because the caller has already done so.
        if debug: print "removing expired session", short(session)
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
    if debug: print "%s: new valid request" % session
    if debug: print "%s: from requesting client at %s" % (short(session), r.hget(session, "client-addr"))
    if debug: print "%s: for %d names: %s" % (short(session), len(names), ", ".join(names))
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
        if debug: print "created new challenge", short(challenge)
    if True:  # challenges have been created
        r.hset(session, "state", "testchallenge")
        r.lpush("pending-testchallenge", session)
        # TODO: this causes the daemon to immediately attempt to test the
        # challenge for completion, with no delay.
        r.publish("requests", "testchallenge")
    else:
        r.lpush("pending-makechallenge", session)
        r.publish("requests", "makechallenge")

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
    # Note that we can push this back into the original queue.
    # TODO: need to add a way to make sure we don't test the same
    # session too often.
    # Conceivably, this could wait until the client announces
    # that it has completed the challenges.  Information about
    # the client's reporting could be stored in the database.
    # Then the CA doesn't need to poll prematurely.
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
        r.publish("requests", "issue")
    else:
        # Some challenges are not verified.
        # Put this session back on the stack to try to verify again.
        r.lpush("pending-testchallenge", session)
        # TODO: if we wanted the client to tell us when it believes
        # it has completed the challenge, we should take this out and
        # have the server publish the message in response to the message
        # from the client.  Also, the current version will cause the
        # server to retest over and over again as fast as it's able.
        r.publish("requests", "testchallenge")

def issue(session):
    if r.hget(session, "live") != "True":
        # This session has died due to some other reason, like an
        # illegal request or timeout, since it entered testchallenge
        # state.  Consequently, we're not allowed to advance its
        # state any further, and it should be removed from the
        # pending-requests queue and not pushed into any other queue.
        # We don't have to remove it from pending-testchallenge
        # because the caller has already done so.
        #
        # Having a session in pending-issue die is a very weird case
        # that probably suggests that timeouts are set incorrectly
        # or that the client is misbehaving very badly.  This means
        # that a request passed all of its challenges but the
        # session nonetheless died for some reason unrelated to failing
        # challenges before the cert could be issued.  Normally, this
        # should never happen.
        #
        # TODO: This can definitely happen when there are extremely many
        # sessions stuck in testchallenge state compared to the number of
        # daemon processes to handle them, because each session in
        # testchallenge gets tested once before any daemon gets around to
        # issuing the cert.  This is a bug.
        if debug: print "removing expired (issue-state!?) session", short(session)
        r.lrem("pending-requests", session)
        return
    csr = r.hget(session, "csr")
    names = r.lrange("%s:names" % session, 0, -1)
    with issue_lock:
        cert = CSR.issue(csr, names)
    r.hset(session, "cert", cert)
    if cert:   # once issuing cert succeeded
        if debug: print "%s: issued certificate for names: %s" % (short(session), ", ".join(names))
        r.hset(session, "state", "done")
        r.lpush("pending-done", session)
        # TODO: Note that we do not publish a pubsub message when
        # the session enters done state, so the daemon will not
        # actually act on it.  Is that OK?
    else:       # should not be reached in deployed version
        if debug: print "issuing for", short(session), "failed"
        r.lpush("pending-issue", session)
        r.publish("requests", "issue")

# Dispatch table for how to react to pubsub messages.  The key is
# the pubsub message and the value is a tuple of (queue name, function).
# The main loop will look in the specified queue for a pending session,
# and, if it finds one, it will call the specified function on it.
# Since the queue names are systematically related to the message names,
# we could probably remove the queue name field entirely.
dispatch = { "makechallenge": ("pending-makechallenge", makechallenge),
             "testchallenge": ("pending-testchallenge", testchallenge),
             "issue":         ("pending-issue", issue),
             "done":          ("pending-done", lambda x: None) }

# Main loop: act on queues notified via Redis pubsub mechanism.
# Currently, we ignore the specific details of which queue was
# notified and, upon any notification, repeatedly process a single
# item from each queue until all queues are empty.

ps.subscribe(["requests"])
ps.subscribe(["logs"])
ps.subscribe(["exit"])
for message in ps.listen():
    if message["type"] != "message":
        continue
    if message["channel"] == "logs":
        if debug: print message["data"]
        continue
    if message["channel"] == "exit":
        break
    if message["channel"] == "requests":
        # populated_queue would be used by a more sophisticated scheduler
        populated_queue = message["data"]
        while True:
            inactive = True
            for queue in ("makechallenge", "testchallenge", "issue"):
                if clean_shutdown:
                    inactive = True
                    break
                session = r.rpop("pending-" + queue)
                if session:
                    inactive = False
                    if ancient(session, queue) and queue != "issue":
                        if debug: print "expiring ancient session", short(session)
                        r.hset(session, "live", False)
                    else:
                        # if debug: print "going to %s for %s" % (queue, short(session))
                        if queue == "makechallenge": makechallenge(session)
                        elif queue == "testchallenge": testchallenge(session)
                        elif queue == "issue": issue(session)
            if inactive:
                break
    
    if clean_shutdown:
        print "daemon exiting cleanly"
        break
