#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
import M2Crypto
import urllib2, os, grp, pwd, sys, time, random, sys, hashlib, subprocess
# It is OK to use the upstream M2Crypto here instead of our modified
# version.

difficulty = 23   # bits of hashcash to generate

def sha256(m):
    return hashlib.sha256(m).hexdigest()

assert len(sys.argv) > 1 or "CHOCOLATESERVER" in os.environ, "Must specify server via command line or CHOCOLATESERVER environment variable."
if len(sys.argv) > 1:
    server = sys.argv[1]
else:
    server = os.environ["CHOCOLATESERVER"]

# it's weird to point to chocolate servers via raw IPv6 addresses, and such
# addresses can be %SCARY in some contexts, so out of paranoia let's disable
# them by default
allow_raw_ipv6_server = False

def is_hostname_sane(hostname):
    """
    Do enough to avoid shellcode from the environment.  There's
    no need to do more.
    """
    import string as s
    allowed = s.ascii_letters + s.digits + "-."  # hostnames & IPv4
    if all([c in allowed for c in hostname])
      return True
    
    if not allow_raw_ipv6_server: return False

    # ipv6 is messy and complicated, can contain %zoneindex etc.  
    import socket
    try:
      # is this a valid IPv6 address?
      socket.getaddrinfo(hostname,443,socket.AF_INET6)
      return True
    except:
      return False

assert is_hostname_sane(server), `server` + " is an impossible hostname"

upstream = "https://%s/chocolate.py" % server

if len(sys.argv) > 3:
    req_file = sys.argv[2]
    key_file = sys.argv[3]
else:
    req_file = "req.pem"
    key_file = "key.pem"

cert_file = "cert.pem"     # we should use getopt to set all of these
chain_file = "chain.pem"

def rsa_sign(key, data):
    """
    Sign this data with this private key.  For client-side use.

    @type key: str
    @param key: PEM-encoded string of the private key.

    @type data: str
    @param data: The data to be signed. Will be hashed (sha256) prior to
    signing.

    @return: binary string of the signature
    """
    key = str(key)
    data = str(data)
    privkey = M2Crypto.RSA.load_key_string(key)
    return privkey.sign(hashlib.sha256(data).digest(), 'sha256')

def do(m):
    u = urllib2.urlopen(upstream, m.SerializeToString())
    return u.read()

def decode(m):
    return (chocolatemessage.FromString(m))

def init(m):
    m.chocolateversion = 1
    m.session = ""

def drop_privs():
    nogroup = grp.getgrnam("nogroup").gr_gid
    nobody = pwd.getpwnam("nobody").pw_uid
    os.setgid(nogroup)
    os.setgroups([])
    os.setuid(nobody)

def make_request(m, csr):
    m.request.recipient = server
    m.request.timestamp = int(time.time())
    m.request.csr = csr
    hashcash_cmd = ["hashcash", "-P", "-m", "-z", "12", "-b", `difficulty`, "-r", server]
    hashcash = subprocess.check_output(hashcash_cmd, preexec_fn=drop_privs, shell=False).rstrip()
    if hashcash: m.request.clientpuzzle = hashcash

def sign(key, m):
    m.request.sig = rsa_sign(key, ("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))

k=chocolatemessage()
m=chocolatemessage()
init(k)
init(m)
make_request(m, csr=open(req_file).read().replace("\r", ""))
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
dn = []
for chall in r.challenge:
    print chall
    if chall.type == r.DomainValidateSNI:
       dvsni_nonce, dvsni_y, dvsni_ext = chall.data
    sni_todo.append( (chall.name, dvsni_y, dvsni_nonce, dvsni_ext) )
    dn.append(chall.name)
    

print sni_todo
import sni_challenge
import configurator

config = configurator.Configurator()
config.get_virtual_hosts()
vhost = set()
for name in dn:
    host = config.choose_virtual_host(name)
    if host is not None:
        vhost.add(host)

if not sni_challenge.perform_sni_cert_challenge(sni_todo, os.path.abspath(req_file), os.path.abspath(key_file), config):
    print "sni_challenge failed"
    sys.exit(1)

print "waiting", 3
time.sleep(3)

r=decode(do(k))
print r
while r.challenge or r.proceed.IsInitialized():
    print "waiting", 5
    time.sleep(5)
    k.session = r.session
    r = decode(do(k))
    print r

# TODO: there should be an unperform_sni_cert_challenge() here.

if r.success.IsInitialized():
    sni_challenge.cleanup(sni_todo, config)
    cert_chain_abspath = None
    with open(cert_file, "w") as f:
        f.write(r.success.certificate)
    if r.success.chain:
        with open(chain_file, "w") as f:
            f.write(r.success.chain)
    print "Server issued certificate; certificate written to " + cert_file
    if r.success.chain: 
        print "Cert chain written to " + chain_file
        # TODO: Uncomment the following assignment when the server 
        #       presents a valid chain
        #cert_chain_abspath = os.path.abspath(chain_file)
    for host in vhost:
        config.deploy_cert(host, os.path.abspath(cert_file), os.path.abspath(key_file), cert_chain_abspath)
    sni_challenge.apache_restart()
elif r.failure.IsInitialized():
    print "Server reported failure."
    sys.exit(1)

# vim: set expandtab tabstop=4 shiftwidth=4
