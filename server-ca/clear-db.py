#!/usr/bin/env python

print "WARNING: Redis database will be cleared!"
raw_input("Press Enter to continue. ")

import redis
r = redis.Redis()

for i in xrange(len(r.keys())):
    r.delete(r.randomkey())
