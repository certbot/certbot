#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
import urllib2, os, sys

try:
    upstream = "https://%s/chocolate.py" % os.environ["CHOCOLATESERVER"]
except KeyError:
    print "Please set the environment variable CHOCOLATESERVER to the hostname"
    print "of a server that speaks this protocol."
    sys.exit(1)

def do(m):
    u = urllib2.urlopen(upstream, m.SerializeToString())
    return u.read()

def decode(m):
    return str(chocolatemessage.FromString(m))

m = chocolatemessage()
