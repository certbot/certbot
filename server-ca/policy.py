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
    #if r.llen("%s:names" % session) > 1:
    #    return True

    # Second example: if any of the names are in the Alexa or Quantcast top
    # 10,000, call for a payment
    names = r.lrange("%s:names" % session, 0, -1)
    for name in names: 
        if in_top_10k(name): return True
    return False

def in_top_10k(hostname):
    """Check whether a hostname is part of a top 10,000 website."""
    # That includes subdomains of top 10,000 sites, but not if the subdomain
    # is below a public suffix (such as a dynamic DNS provider or hosting
    # umbrella, perhaps)
    parts = hostname.lower().split(".")
    for n in range(2, len(parts)+1):
      name_or_parent = ".".join(parts[-n:])
      if name_or_parent in top_10k:
        return True
      # XXX if name_or_parent in public_suffix_list: break
    return False

def check_domain(domain):
    import string as s
    allowed = s.ascii_letters + s.digits + "-."  
    # top 10k domains should contain dots, and ASCII characters (for the TLD,
    # if nothing else).  
    # XXX The Alexa top10k contains a few IP addresses.  This currently
    # excludes them, but perhaps it shouldn't...
    if len([c for c in domain if c in s.ascii_letters]) == 0: return False
    if "." not in domain: return False
    return all([c in allowed for c in domain])

have_top_10k = False

def get_top_10k():
    data_files = ["data/alexa-top-10k.txt","data/quantast-top-10k.txt"]
    global top_10k, have_top_10k
    top_10k = {}
    for f in data_files:
        for line in open(f).readlines():
            domain=line.split()[1]
            if check_domain(domain):
                top_10k[domain] = True
    have_top_10k = True

get_top_10k()

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
