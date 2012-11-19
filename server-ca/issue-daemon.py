#!/usr/bin/env python

# This daemon runs on the CA side to look for requests in
# the database that are waiting for a cert to be issued.

import redis, redis_lock, CSR, sys, signal
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

debug = "debug" in sys.argv
clean_shutdown = False

from daemon_common import signal_handler, short, random, random_raw, log

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

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
        log("removing expired (issue-state!?) session", session)
        r.lrem("pending-requests", session)
        return
    if r.hget(session, "state") != "issue":
        return
    csr = r.hget(session, "csr")
    names = r.lrange("%s:names" % session, 0, -1)
    log("attempting to issue certificate for names: %s" % ", ".join(names), session)
    with issue_lock:
        cert = CSR.issue(csr, names)
    r.hset(session, "cert", cert)
    if cert:   # once issuing cert succeeded
        log("issued certificate for names: %s" % ", ".join(names), session)
        r.hset(session, "state", "done")
        # r.lpush("pending-done", session)
    else:       # should not be reached in deployed version
        log("issuing cert failed!?", session)
        r.lpush("pending-issue", session)

while True:
    (where, what) = r.brpop(["exit", "pending-issue"])
    if where == "exit":
        r.lpush("exit", "exit")
        break
    elif where == "pending-issue":
        issue(what)
    if clean_shutdown:
        print "issue daemon exiting cleanly"
        break
