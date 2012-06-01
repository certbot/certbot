#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
from Crypto.Hash import SHA256
import urllib2, os, sys, time, random, CSR

def sha256(m):
    return SHA256.new(m).hexdigest()

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

def init(m):
    m.chocolateversion = 1
    m.session = ""

def make_request(m):
    m.request.add()
    m.request[0].nonce = "".join([random.choice("abcdefghijklmnopqrstuvwxyz") for i in xrange(20)])
    m.request[0].recipient = "ca.example.com"
    m.request[0].timestamp = int(time.time())
    m.request[0].csr = "FOO"
    m.request[0].sig = "BAR"

def sign(k, m, i=0):
    m.request[i].sig = CSR.sign(k, sha256("(%d) (%s) (%s) (%s)" % (m.request[i].timestamp, m.request[i].recipient, m.request[i].nonce, m.request[i].csr)))

m = chocolatemessage()

