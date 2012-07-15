#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
import CSR
from CSR import M2Crypto
import urllib2, os, sys, time, random, sys, hashlib, hashcash
# CSR.py here should be a symlink to ../server-ca/CSR.py
# hashcash.py here should be a symlink to ../server-ca/hashcash.py

difficulty = 20
# TODO: unfortunately, the C hashcash implementation seems to be about
#       2^6 times faster than the native Python implementation, so
#       calibrating the difficulty is a bit of a problem.

def sha256(m):
    return hashlib.sha256(m).hexdigest()

assert len(sys.argv) > 1 or "CHOCOLATESERVER" in os.environ, "Must specify server via command line or CHOCOLATESERVER environment variable."
if len(sys.argv) > 1:
    server = sys.argv[1]
else:
    server = os.environ["CHOCOLATESERVER"]

upstream = "https://%s/chocolate.py" % server

if len(sys.argv) > 3:
    req_file = sys.argv[2]
    key_file = sys.argv[3]
else:
    req_file = "req.pem"
    key_file = "key.pem"

cert_file = "cert.pem"     # we should use getopt to set all of these

def do(m):
    u = urllib2.urlopen(upstream, m.SerializeToString())
    return u.read()

def decode(m):
    return (chocolatemessage.FromString(m))

def init(m):
    m.chocolateversion = 1
    m.session = ""

def make_request(m, csr):
    m.request.recipient = server
    m.request.timestamp = int(time.time())
    m.request.csr = csr
    m.request.clientpuzzle = hashcash.mint(server, difficulty)

def sign(key, m):
    m.request.sig = CSR.sign(key, ("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))

k=chocolatemessage()
m=chocolatemessage()
init(k)
init(m)
make_request(m, csr=open(reqfile).read())
sign(open(key_file).read(), m)
print m
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

sni_challenge.perform_sni_cert_challenge(sni_todo, req_file, key_file)

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
    with open(cert_file, "w") as f:
        f.write(r.success.certificate)
    print "Server issued certificate; certificate written to " + cert_file
elif r.failure.IsInitialized():
    print "Server reported failure."
    sys.exit(1)
