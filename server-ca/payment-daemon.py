#!/usr/bin/env python

# Wait for news about payments received for sesssions and
# then mark the sessions to show that that payment was received.

# The reason that this is separate from payment.py (which
# simulates actually processing a credit card payment) is
# to make the security analysis simpler and cleaner and
# reduce attack surface.  The idea is that payment.py decides
# whether someone has paid, but NOT whether the certificate
# has been granted.  This daemon decides whether the
# certificate should be granted, but NOT whether someone has
# paid.  Thus, payment.py does not need, or exercise, the
# power to change session status directly.

# This preserves the rule that session status is only ever
# advanced by the appropriate daemon (though a session may
# be killed by any part of the system that identifies a
# fatal problem or protocol violation).

# This daemon uses a different scheduling model from the
# testchallenge daemon so ONLY ONE COPY OF THIS DAEMON SHOULD
# BE RUN AT ONCE.  Since this daemon takes a minimal, discrete
# action in response to a pubsub message, there should never be
# a significant backlog associated with this daemon.

import redis, signal, sys

r = redis.Redis()
ps = r.pubsub()

debug = "debug" in sys.argv
clean_shutdown = False

from daemon_common import signal_handler

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

ps.subscribe(["payments", "exit"])
for message in ps.listen():
    if message["type"] != "message":
        continue
    if message["channel"] == "payments":
        if debug: print message["data"]
        session = message["data"]
        if len(session) != 64: continue
        if session not in r or r.hget(session, "live") != "True": continue
        if r.hget(session, "state") != "payment": continue
        if debug: print "\t** All challenges satisfied; payment received; request %s GRANTED" % short(session)
        r.hset(session, "state", "issue")
        r.lpush("pending-issue", session)
        continue
    if message["channel"] == "exit":
        break
    if clean_shutdown:
        print "daemon exiting cleanly"
        break
