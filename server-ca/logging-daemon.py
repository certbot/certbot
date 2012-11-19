#!/usr/bin/env python

# This daemon runs on the CA side to handle logging.

import redis, signal, sys

r = redis.Redis()
ps = r.pubsub()

debug = "debug" in sys.argv
clean_shutdown = False

from daemon_common import signal_handler, log

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

ps.subscribe(["logs", "exit"])
for message in ps.listen():
    if message["type"] != "message":
        continue
    if message["channel"] == "logs":
        sys.stdout.write(message["data"] + "\n")
        sys.stdout.flush()
        continue
    if message["channel"] == "exit":
        break
    if clean_shutdown:
        print "logging daemon exiting cleanly"
        break
