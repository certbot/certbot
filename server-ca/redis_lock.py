#!/usr/bin/env python

# This is an attempt at implementing the locking algorithm described at
#                http://redis.io/commands/setnx
# as a Python lock object that can be used with the Python "with"
# statement.  To use:
#
# lock = redis_lock(redis_instance, "name")
# with lock:
#      # do stuff guarded by the lock
#
# Only one process will be able to enter the block at a time for a
# given Redis instance and name, as long as the most recent process
# to enter the block did so less than timeout seconds ago.  All
# processes attempting to acquire the lock will poll to see if it
# is released or expires.  If the algorithm is correct and correctly
# implemented, only one process succeds in clearing and acquiring a
# particular expired lock, even "when multiple clients detected an
# expired lock and are trying to release it".
#
# The optional one_shot parameter causes the attempt to acquire the
# lock to instead raise a KeyError exception if someone else is already
# holding a valid lock.

import time, random

timeout = 60

def valid(t):
    """Is a lock with expiry time t now valid (not expired)?"""
    return float(t) > time.time()

class redis_lock(object):
    def __init__(self, redis, lock_name, one_shot=False):
        self.redis = redis
        self.lock_name = lock_name
        self.one_shot = one_shot

    def __enter__(self):
        while True:
            self.expiry = time.time() + timeout
            # "C4 sends SETNX lock.foo in order to acquire the lock"
            if self.redis.setnx(self.lock_name, self.expiry + 1):
                return
            # "C4 sends GET lock.foo to check if the lock expired."
            existing_lock = self.redis.get(self.lock_name)
            if (not existing_lock) or valid(existing_lock):
                if self.one_shot:
                    raise KeyError
                # "If it is not, it will sleep for some time and retry from
                # the start."
                time.sleep(1 + random.random())
                continue
            else:
                # "Instead, if the lock is expired because the Unix time at
                # lock.foo is older than the current Unix time, C4 tries to
                # perform: GETSET lock.foo [...]"
                result = self.redis.getset(self.lock_name, self.expiry + 1)
                if not valid(result):
                    # "C4 can check if the old value stored at key is still
                    # an expired timestamp. If it is, the lock was acquired."
                    return
                else:
                    # "If another client [...] was faster than C4 and acquired
                    # the lock with the GETSET operation, the C4 GETSET
                    # operation will return a non expired timestamp. C4 will
                    # simply restart from the first step."
                    continue

    def __exit__(self, exception_type, exception_value, traceback):
        # "[...] a client holding a lock should always check the timeout
        # didn't expire before unlocking the key with DEL [...]"
        if valid(self.expiry):
            self.redis.delete(self.lock_name)
        # This may be redundant.  We have the ability to cancel exceptions
        # that occur inside the with block, but we currently don't exercise
        # this ability.
        if exception_value is None:
            return True
