#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
import urllib2, os, sys, time

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

def make_request(m):
    m.request.add()
    m.request[0].nonce = "blah"
    m.request[0].recipient = "ca.example.com"
    m.request[0].timestamp = int(time.time())
    m.request[0].csr = "FOO"
    m.request[0].sig = "BAR"

m = chocolatemessage()

