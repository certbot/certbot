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
    m.request.nonce = "".join([random.choice("abcdefghijklmnopqrstuvwxyz") for i in xrange(20)])
    m.request.recipient = "ca.example.com"
    m.request.timestamp = int(time.time())
    m.request.csr = "FOO"
    m.request.sig = "BAR"

def sign(k, m):
    m.request.sig = CSR.sign(k, sha256("(%d) (%s) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.nonce, m.request.csr)))

m = chocolatemessage()

