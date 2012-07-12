#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
from Crypto.Hash import SHA256
import M2Crypto
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
    return (chocolatemessage.FromString(m))

def init(m):
    m.chocolateversion = 1
    m.session = ""

def make_request(m):
    # m.request.nonce = "".join([random.choice("abcdefghijklmnopqrstuvwxyz") for i in xrange(20)])
    m.request.recipient = "ca.example.com"
    m.request.timestamp = int(time.time())
    m.request.csr = "FOO"
    m.request.sig = "BAR"

def sign(k, m):
    m.request.sig = CSR.sign(k, sha256("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))

k=chocolatemessage()
m=chocolatemessage()
init(k)
init(m)
make_request(m)
m.request.csr = open("req.pem").read()
sign(open("key.pem").read(), m)
r=decode(do(m))
print r
while r.proceed.IsInitialized():
   if r.proceed.polldelay > 60: r.proceed.polldelay = 60
   print "waiting", r.proceed.polldelay
   time.sleep(r.proceed.polldelay)
   k.session = r.session
   r = decode(do(k))
   print r

sni_todo = []
for chall in r.challenge:
    print chall
    if chall.type == r.DomainValidateSNI:
       dvsni_nonce, dvsni_y, dvsni_ext = chall.data
#       key = M2Crypto.RSA.load_key_string(open("key.pem").read())
#       dvsni_r = key.private_decrypt(dvsni_y, M2Crypto.RSA.pkcs1_oaep_padding)
    sni_todo.append( (chall.name, dvsni_y, dvsni_nonce, dvsni_ext) )

print sni_todo
import sni_challenge

sni_challenge.perform_sni_cert_challenge(sni_todo, "req.pem", "key.pem")

r=decode(do(k))
print r
while r.challenge or r.proceed.IsInitialized():
    print "waiting", 5
    time.sleep(5)
    k.session = r.session
    r = decode(do(k))
    print r
