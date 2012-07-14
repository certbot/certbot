#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
from Crypto.Hash import SHA256
import CSR
from CSR import M2Crypto
import urllib2, os, sys, time, random, sys
# CSR.py here should be a symlink to ../server-ca/CSR.py

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

def make_request(m, csr):
    # TODO: take recipient from os.environ["CHOCOLATESERVER"]
    m.request.recipient = "ca.example.com"
    m.request.timestamp = int(time.time())
    m.request.csr = csr

def sign(k, m):
    m.request.sig = CSR.sign(k, ("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))

k=chocolatemessage()
m=chocolatemessage()
init(k)
init(m)
make_request(m, csr=open("req.pem").read())
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

if r.failure.IsInitialized():
    print "Server reported failure."
    sys.exit(1)

sni_todo = []
for chall in r.challenge:
    print chall
    if chall.type == r.DomainValidateSNI:
       dvsni_nonce, dvsni_y, dvsni_ext = chall.data
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

# TODO: there should be an unperform_sni_cert_challenge() here.
# TODO: there should be a deploy_cert() here.

if r.success.IsInitialized():
    open("cert.pem", "w").write(r.success.certificate)
    print "Server issued certificate; certificate written to cert.pem"
elif r.failure.IsInitialized():
    print "Server reported failure."
    sys.exit(1)
