#!/usr/bin/env python

import M2Crypto
# It is OK to use the upstream M2Crypto here instead of our modified
# version.
import urllib2
import os, grp, pwd, sys, time, random, sys
import hashlib
import subprocess
import getopt
# TODO: support a mode where use of interactive prompting is forbidden

from trustify.protocol.chocolate_pb2 import chocolatemessage
from trustify.client import sni_challenge
from trustify.client import configurator
from trustify.client.CONFIG import difficulty, cert_file, chain_file
from trustify.client.CONFIG import SERVER_ROOT

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

def choice_of_ca():
    # XXX This is a stub
    d = dialog.Dialog()
    choices = [("EFF", "The EFF Trustify CA"), ("UMich", "The Michigan Trustify CA")]
    random.shuffle(choices)
    result = d.menu("Pick a Certificate Authority.  They're all unique and special!", width=70, choices=choices)


# based on M2Crypto unit test written by Toby Allsopp
from M2Crypto import EVP, X509, RSA

def make_key_and_csr(names, bits=2048):
    """Return a tuple (key, csr) containing a PEM-formatted private key
    of the specified number of bits and a CSR requesting a certificate for
    the specified DNS names."""
    assert names, "Must provide one or more hostnames."
    pk = EVP.PKey()
    x = X509.Request()
    rsa = RSA.gen_key(bits, 65537)
    pk.assign_rsa(rsa)
    key_pem = rsa.as_pem(cipher=None)
    rsa = None # should not be freed here
    x.set_pubkey(pk)
    name = x.get_subject()
    name.CN = names[0]
    extstack = X509.X509_Extension_Stack()
    for n in names:
        ext = X509.new_extension('subjectAltName', 'DNS:%s' % n)
        extstack.push(ext)
    x.add_extensions(extstack)
    x.sign(pk,'sha1')
    assert x.verify(pk)
    pk2 = x.get_pubkey()
    assert x.verify(pk2)
    return key_pem, x.as_pem()

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

def make_request(server, m, csr, quiet=False):
    m.request.recipient = server
    m.request.timestamp = int(time.time())
    m.request.csr = csr
    hashcash_cmd = ["hashcash", "-P", "-m", "-z", "12", "-b", `difficulty`, "-r", server]
    if quiet:
        hashcash = subprocess.check_output(hashcash_cmd, preexec_fn=drop_privs, shell=False, stderr=open("/dev/null", "w")).rstrip()
    else:
        hashcash = subprocess.check_output(hashcash_cmd, preexec_fn=drop_privs, shell=False).rstrip()
    if hashcash: m.request.clientpuzzle = hashcash

def sign(key, m):
    m.request.sig = rsa_sign(key, ("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))

def save_key_csr(key, csr):
    """
    This function saves the newly generated key and csr to new files
    in the ssl and certs directories respectively
    This function sets the appropriate permissions for the key and its
    directory.
    """
    # Create directories if they do not exist
    if not os.path.isdir(SERVER_ROOT + "certs"):
        os.makedirs(SERVER_ROOT + "certs")
    if not os.path.isdir(SERVER_ROOT + "ssl"):
        os.makedirs(SERVER_ROOT + "ssl")
        # Need leading 0 for octal integer
        os.chmod(SERVER_ROOT + "ssl", 0700)
    # Write key to new file and change permissions
    key_fn = find_file_name(SERVER_ROOT + "ssl/key-trustify")
    key_f = open(key_fn, 'w')
    key_f.write(key)
    key_f.close()
    os.chmod(key_fn, 0600)
    # Write CSR to new file
    csr_fn = find_file_name(SERVER_ROOT + "certs/csr-trustify")
    csr_f = open(csr_fn, 'w')
    csr_f.write(csr)
    csr_f.close()
        
    return key_fn, csr_fn

def find_file_name(default_name):
    count = 2
    name = default_name
    while os.path.isfile(name):
        name = default_name + "_" + str(count)
        count += 1
    return name

def authenticate():
    """
    Main call to do DV_SNI validation and deploy the trustify certificate
    TODO: This should be turned into a class...
    """
    global server, names, csr, privkey
    if "CHOCOLATESERVER" in os.environ:
        server = os.environ["CHOCOLATESERVER"]
    if not server:
        # Global default value for Chocolate server!
        server = "ca.theobroma.info"

    assert is_hostname_sane(server), `server` + " is an impossible hostname"

    upstream = "https://%s/chocolate.py" % server
    config = configurator.Configurator()

    if not names:
        #names = ["example.com", "www.example.com", "foo.example.com"]
	names = config.get_all_names()

    if curses:
        names = filter_names(names)
        choice_of_ca()
        shower = progress_shower()

    # Check first if mod_ssl is loaded
    if not config.check_ssl_loaded():
        if curses:
            shower.add("Loading mod_ssl into Apache Server")
        else:
            print "Loading mod_ssl into Apache Server"
        config.enable_mod_ssl()

    req_file = csr
    key_file = privkey
    if csr and privkey:
        csr_pem = open(req_file).read().replace("\r", "")
        key_pem = open(key_file).read().replace("\r", "")
    if not csr or not privkey:
        # Generate new private key and corresponding csr!
        key_pem, csr_pem = make_key_and_csr(names, 2048)
        key_file, req_file = save_key_csr(key_pem, csr_pem)
        if curses:
            shower.add("Generating key: " + key_file + "\n")
            shower.add("Creating CSR: " + req_file + "\n")
        else:
            print "Generating key:", key_file
            print "Creating CSR:", req_file

    k=chocolatemessage()
    m=chocolatemessage()
    init(k)
    init(m)
    if curses:
        shower.add("Creating request; generating hashcash...\n")
    make_request(server, m, csr_pem, quiet=curses)
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
           shower.add("Waiting %d seconds...\n" % r.proceed.polldelay)
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
        shower.add("Received %s challenges from server.\n" % len(r.challenge))
    for chall in r.challenge:
        if not curses: print chall
        if chall.type == r.DomainValidateSNI:
            if curses:
               shower.add("\tDomainValidateSNI challenge for name %s.\n" % chall.name)
            dvsni_nonce, dvsni_y, dvsni_ext = chall.data
        sni_todo.append( (chall.name, dvsni_y, dvsni_nonce, dvsni_ext) )
        dn.append(chall.name)


    if not curses: print sni_todo

    # Find virtual hosts to deploy certificates too
    vhost = set()
    for name in dn:
        host = config.choose_virtual_host(name)
        if host is not None:
            vhost.add(host)

    if not sni_challenge.perform_sni_cert_challenge(sni_todo, os.path.abspath(req_file), os.path.abspath(key_file), config, quiet=curses):
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
            # Enable any vhost that was issued to, but not enabled
            if not config.is_site_enabled(host.file):
                if curses:
                    shower.add("Enabling Site " + host.file)
                else:
                    print "Enabling Site", host.file
                config.enable_site(host.file)

        sni_challenge.apache_restart(quiet=curses)
    elif r.failure.IsInitialized():
        print "Server reported failure."
        sys.exit(1)

# vim: set expandtab tabstop=4 shiftwidth=4
