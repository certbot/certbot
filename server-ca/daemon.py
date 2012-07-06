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
# Generally, the server is not supposed to change sessions
# very much once they have been added to a queue, except
# for marking them no longer live if the server realizes
# that something bad has happened to them.  There may be
# some exceptions, and they should all be analyzed for
# possible races.

# TODO: The daemon should probably check for timeouts before
# advancing sessions' state.  Currently timeouts can only
# happen if something other than the daemon notices them,
# which currently can only happen when the client checks in.
# If the client never checks in, the daemon can keep advancing
# the request's state, which may not be the right behavior.

import redis, time, CSR
r = redis.Redis()

from Crypto.Hash import SHA256, HMAC
from Crypto import Random

def sha256(m):
    return SHA256.new(m).hexdigest()

def hmac(k, m):
    return HMAC.new(k, m, SHA256).hexdigest()

def random():
    """Return 64 hex digits representing a new 32-byte random number."""
    return sha256(Random.get_random_bytes(32))

def random_raw():
    """Return 32 random bytes."""
    return SHA256.new(Random.get_random_bytes(32)).digest()

def makechallenge(session):
    if r.hget(session, "live") != "True":
        # This session has died due to some other reason, like an
        # illegal request or timeout, since it entered makechallenge
        # state.  Consequently, we're not allowed to advance its
        # state any further, and it should be removed from the
        # pending-requests queue and not pushed into any other queue.
        # We don't have to remove it from pending-makechallenge
        # because the caller has already done so.
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
    for i, name in enumerate(r.lrange("%s:names" % session, 0, -1)):
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
    if True:  # challenges have been created
        r.hset(session, "state", "testchallenge")
        r.lpush("pending-testchallenge", session)
    else:
        r.lpush("pending-makechallenge", session)

def testchallenge(session):
    if r.hget(session, "live") != "True":
        # This session has died due to some other reason, like an
        # illegal request or timeout, since it entered testchallenge
        # state.  Consequently, we're not allowed to advance its
        # state any further, and it should be removed from the
        # pending-requests queue and not pushed into any other queue.
        # We don't have to remove it from pending-testchallenge
        # because the caller has already done so.
        r.lrem("pending-requests", session)
        return
    # Note that we can push this back into the original queue.
    # TODO: need to add a way to make sure we don't test the same
    # session too often.
    # Conceivably, this could wait until the client announces
    # that it has completed the challenges.  Information about
    # the client's reporting could be stored in the database.
    # Then the CA doesn't need to poll prematurely.
    if False:  # if challenges all succeed
        r.hset(session, "state", "issue")
        r.lpush("pending-issue", session)
    else:
        r.lpush("pending-testchallenge", session)
    # can also cause a failure under some conditions, causing the
    # session to become dead.  TODO: need to articulate what those
    # conditions are

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
        r.lrem("pending-requests", session)
        return
    # Note that we can push this back into the original queue.
    # TODO: need to add a way to make sure we don't test the same
    # TODO: actually make this call issue the cert
    csr = r.hget(session, "csr")
    cert = CSR.issue(csr)
    r.hset(session, "cert", cert)
    if False:   # once issuing cert succeeded
        r.hset(session, "state", "done")
        r.lpush("pending-done", session)
    else:       # should not be reached in deployed version
        r.lpush("pending-issue", session)

while True:
    session = r.rpop("pending-makechallenge")
    if session:
        makechallenge(session)
        session = None
    else: session = r.rpop("pending-testchallenge")
    if session:
        testchallenge(session)
        session = None
    else: session = r.rpop("pending-issue")
    if session:
        issue(session)
        session = None
    else: time.sleep(2)
    # This daemon doesn't currently act on pending-done sessions.
