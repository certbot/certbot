#!/usr/bin/env python

from chocolate_protocol_pb2 import chocolatemessage
import M2Crypto
# It is OK to use the upstream M2Crypto here instead of our modified
# version.
import urllib2, os, grp, pwd, sys, time, random, sys, hashlib, subprocess
import getopt
# TODO: support a mode where use of interactive prompting is forbidden

import sni_challenge
import configurator
#from trustify import sni_challenge
#from trustify import configurator

# bits of hashcash to generate
from CONFIG import difficulty
#from trustify.CONFIG import difficulty

#Trustify certificate and chain files
from CONFIG import cert_file, chain_file
#from trustify.CONFIG import cert_file, chain_file

# it's weird to point to chocolate servers via raw IPv6 addresses, and such
# addresses can be %SCARY in some contexts, so out of paranoia let's disable
# them by default
allow_raw_ipv6_server = False

opts = getopt.getopt(sys.argv[1:], "", ["text", "privkey=", "csr=", "server="])

curses = True
csr = None
privkey = None
server = None
for opt in opts[0]:
    if opt[0] == "--text":
        curses = False
    if opt[0] == "--csr":
        csr = opt[1]
    if opt[0] == "--privkey":
        privkey = opt[1]
    if opt[0] == "--server":
        server = opt[1]
names = opts[1]

if curses:
    import dialog

def sha256(m):
    return hashlib.sha256(m).hexdigest()

def filter_names(names):
    d = dialog.Dialog()
    choices = [(n, "", 1) for n in names]
    result = d.checklist("Which names would you like to activate HTTPS for?", choices=choices)
    if result[0] != 0 or not result[1]:
        sys.exit(1)
    return result[1]

def by_default():
    d = dialog.Dialog()
    choices = [("Easy", "Allow both HTTP and HTTPS access to these sites"), ("Secure", "Make all requests redirect to secure HTTPS access")]
    result = d.menu("Please choose whether HTTPS access is required or optional.", width=70, choices=choices)
    if result[0] != 0:
        sys.exit(1)
    return result[1] == "Secure"

class progress_shower(object):
    # As in "that which shows", not like a rain shower.
    def __init__(self, firstmessage="", height=18, width=70):
        self.content = firstmessage
        self.d = dialog.Dialog()
        self.height = height
        self.width = width
        self.show()

    def add(self, s):
        self.content += s
        self.show()

    def show(self):
        self.d.infobox(self.content, self.height, self.width)

def is_hostname_sane(hostname):
    """
    Do enough to avoid shellcode from the environment.  There's
    no need to do more.
    """
    import string as s
    allowed = s.ascii_letters + s.digits + "-."  # hostnames & IPv4
    if all([c in allowed for c in hostname]):
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

def do(upstream, m):
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

def make_request(server, m, csr):
    m.request.recipient = server
    m.request.timestamp = int(time.time())
    m.request.csr = csr
    hashcash_cmd = ["hashcash", "-P", "-m", "-z", "12", "-b", `difficulty`, "-r", server]
    hashcash = subprocess.check_output(hashcash_cmd, preexec_fn=drop_privs, shell=False).rstrip()
    if hashcash: m.request.clientpuzzle = hashcash

def sign(key, m):
    m.request.sig = rsa_sign(key, ("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))


def authenticate():
    """
    Main call to do DV_SNI validation and deploy the trustify certificate
    TODO: This should be turned into a class...
    """
    global server, names, csr, privkey
    assert server or "CHOCOLATESERVER" in os.environ, "Must specify server via command line or CHOCOLATESERVER environment variable."
    if "CHOCOLATESERVER" in os.environ:
        server = os.environ["CHOCOLATESERVER"]

    assert is_hostname_sane(server), `server` + " is an impossible hostname"

    upstream = "https://%s/chocolate.py" % server

    if not names:
        # TODO: automatically import names from Apache config
        names = ["example.com", "www.example.com", "foo.example.com"]

    if curses:
        names = filter_names(names)

    req_file = csr
    key_file = privkey
    if csr and privkey:
        csr_pem = open(req_file).read().replace("\r", "")
        key_pem = open(key_file).read().replace("\r", "")
    if not csr or not privkey:
        # Generate new private key and corresponding csr!
        key_pem, csr_pem = makerequest(2048, names)
        # TODO: IMPORTANT: NEED TO SAVE THESE TO FILES

    if curses:
        shower = progress_shower()
    k=chocolatemessage()
    m=chocolatemessage()
    init(k)
    init(m)
    if curses:
        shower.add("Creating request; generating hashcash...\n")
    make_request(server, m, csr_pem)
    sign(key_pem, m)
    if curses:
        shower.add("Created request; sending to server...\n")
    else:
        print m
    r=decode(do(upstream, m))
    if not curses: print r
    while r.proceed.IsInitialized():
       if r.proceed.polldelay > 60: r.proceed.polldelay = 60
       if curses:
           shower.add("Waiting %d...\n" % r.proceed.polldelay)
       else:
           print "waiting", r.proceed.polldelay
       time.sleep(r.proceed.polldelay)
       k.session = r.session
       r = decode(do(upstream, k))
       if not curses: print r

    if r.failure.IsInitialized():
        print "Server reported failure."
        sys.exit(1)

    sni_todo = []
    dn = []
    if curses:
        shower.add("Received %s challenges.\n" % len(r.challenge))
    for chall in r.challenge:
        if not curses: print chall
        if chall.type == r.DomainValidateSNI:
           dvsni_nonce, dvsni_y, dvsni_ext = chall.data
        sni_todo.append( (chall.name, dvsni_y, dvsni_nonce, dvsni_ext) )
        dn.append(chall.name)


    if not curses: print sni_todo

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
    if curses: shower.add("Configured Apache for challenge; waiting for verification...\n")

    if not curses: print "waiting", 3
    time.sleep(3)

    r=decode(do(upstream, k))
    if not curses: print r
    while r.challenge or r.proceed.IsInitialized():
        if not curses: print "waiting", 5
        time.sleep(5)
        k.session = r.session
        r = decode(do(upstream, k))
        if not curses: print r

    if r.success.IsInitialized():
        sni_challenge.cleanup(sni_todo, config)
        cert_chain_abspath = None
        with open(cert_file, "w") as f:
            f.write(r.success.certificate)
        if r.success.chain:
            with open(chain_file, "w") as f:
                f.write(r.success.chain)
        if curses:
            shower.add("Server issued certificate; certificate written to %s\n" % cert_file)
        else:
            print "Server issued certificate; certificate written to " + cert_file
        if r.success.chain: 
            if curses:
                shower.add("Cert chain written to %s\n" % chain_file)
            else:
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

if __name__ == "__main__":
    authenticate()
