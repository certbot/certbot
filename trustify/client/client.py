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
from trustify.client.sni_challenge import SNI_Challenge
from trustify.client import configurator
from trustify.client import logger
from trustify.client.CONFIG import difficulty, cert_file, chain_file
from trustify.client.CONFIG import KEY_DIR, CERT_DIR

# it's weird to point to chocolate servers via raw IPv6 addresses, and such
# addresses can be %SCARY in some contexts, so out of paranoia let's disable
# them by default
allow_raw_ipv6_server = False

opts = getopt.getopt(sys.argv[1:], "", ["text", "privkey=", "csr=", "server="])

curses = True
shower = None
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
        hashcash = subprocess.Popen(hashcash_cmd, preexec_fn=drop_privs, shell= False, stdout=subprocess.PIPE, stderr=open("/dev/null", "w")).communicate()[0].rstrip()
    else:
        hashcash = subprocess.Popen(hashcash_cmd, preexec_fn=drop_privs, shell= False, stdout=subprocess.PIPE).communicate()[0].rstrip()

    if hashcash: m.request.clientpuzzle = hashcash

def sign(key, m):
    m.request.sig = rsa_sign(key, ("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))

def old_cert(cert_filename, days_left):
    cert = M2Crypto.X509.load_cert(cert_filename)
    exp_time = cert.get_not_before().get_datetime()
    cur_time = datetime.datetime.utcnow()

    # exp_time is returned in UTC time as defined by M2Crypto
    # The datetime object is aware and cannot be compared to the naive utcnow()
    # object. Thus, the tzinfo is stripped from exp_time assuming both objects
    # are UTC.  Base python doesn't seem to support instantiations of tzinfo
    # objects without 3rd party support.  It is easier just to strip tzinfo from
    # exp_time rather than add the utc timezone to cur_time
    if (exp_time.replace(tzinfo=None) - cur_time).days < days_left:
        return True
    return False

def save_key_csr(key, csr):
    """
    This function saves the newly generated key and csr to new files
    in the ssl and certs directories respectively
    This function sets the appropriate permissions for the key and its
    directory.
    """
    # Create directories if they do not exist
    # This should probably go in the installation script
    # Make sure directories exist & make sure directories are set with the
    # correct permissions if they do exist.
    if not os.path.isdir(CERT_DIR):
        os.makedirs(CERT_DIR, 0755)
    if not os.path.isdir(KEY_DIR):
        os.makedirs(KEY_DIR, 0700)

    # Write key to new file and change permissions
    key_f, key_fn = unique_file(KEY_DIR + "key-trustify.pem", 0600)
    key_f.write(key)
    key_f.close()
    # Write CSR to new file
    csr_f, csr_fn = unique_file(CERT_DIR + "csr-trustify.pem", 0644)
    csr_f.write(csr)
    csr_f.close()
        
    return key_fn, csr_fn

def recognized_ca(issuer):
    pass

def gen_req_from_cert():
    return

def unique_file(default_name, mode = 0777):
    """
    Safely finds a unique file for writing only (by default)
    """
    count = 1
    f_parsed = os.path.splitext(default_name)
    while 1:
        try:
            fd = os.open(default_name, os.O_CREAT|os.O_EXCL|os.O_RDWR, mode)
            return os.fdopen(fd, 'w'), default_name
        except OSError:
            pass
        default_name = f_parsed[0] + '_' + str(count) + f_parsed[1]
        count += 1

def gen_https_names(domains):
    """
    Returns a string of the domains formatted nicely with https:// prepended
    to each
    """
    result = ""
    if len(domains) > 2:
        for i in range(len(domains)-1):
            result = result + "https://" + domains[i] + ", "
        result = result + "and "
    if len(domains) == 2:
        return "https://" + domains[0] + " and https://" + domains[1]
    result = result + "https://" + domains[len(domains)-1]
    return result

def challenge_factory(r, req_filepath, key_filepath, config):
    sni_todo = []
    dn = []
    challenges = []
    logger.info("Received %s challenges from server." % len(r.challenge))
    for chall in r.challenge:
        logger.debug(chall)
        if chall.type == r.DomainValidateSNI:
            logger.info("\tDomainValidateSNI challenge for name %s." % chall.name)
            dvsni_nonce, dvsni_y, dvsni_ext = chall.data
            sni_todo.append( (chall.name, dvsni_y, dvsni_nonce, dvsni_ext) )
            
        dn.append(chall.name)
    if sni_todo:
        challenges.append(SNI_Challenge(sni_todo, req_filepath, key_filepath, config))
        logger.debug(sni_todo)

    return challenges, dn
        

def send_request(key_pem, csr_pem, quiet=curses):
    global server
    upstream = "https://%s/chocolate.py" % server
    k=chocolatemessage()
    m=chocolatemessage()
    init(k)
    init(m)
    logger.info("Creating request; generating hashcash...")
    make_request(server, m, csr_pem, quiet=curses)
    sign(key_pem, m)
    logger.info("Created request; sending to server...")
    logger.debug(m)

    r=decode(do(upstream, m))
    logger.debug(r)
    while r.proceed.IsInitialized():
       if r.proceed.polldelay > 60: r.proceed.polldelay = 60
       logger.info("Waiting %d seconds..." % r.proceed.polldelay)
       time.sleep(r.proceed.polldelay)
       k.session = r.session
       r = decode(do(upstream, k))
       logger.debug(r)

    if r.failure.IsInitialized():
        logger.fatal("Chocolate Server reported failure.")
        sys.exit(1)
        
    return r, k


def handle_verification_response(r, dn, challenges, vhost, key_file, config):
    if r.success.IsInitialized():
        for chall in challenges:
            chall.cleanup()
        cert_chain_abspath = None
        with open(cert_file, "w") as f:
            f.write(r.success.certificate)

        logger.info("Server issued certificate; certificate written to %s" % cert_file)
        if r.success.chain:
            with open(chain_file, "w") as f:
                f.write(r.success.chain)
 
            logger.info("Cert chain written to %s" % chain_file)

            # This expects a valid chain file
            cert_chain_abspath = os.path.abspath(chain_file)

        for host in vhost:
            config.deploy_cert(host, os.path.abspath(cert_file), os.path.abspath(key_file), cert_chain_abspath)
            # Enable any vhost that was issued to, but not enabled
            if not host.enabled:
                logger.info("Enabling Site " + host.file)
                config.enable_site(host)

        # sites may have been enabled / final cleanup
        config.restart(quiet=curses)

        if curses:
            dialog.Dialog().msgbox("\nCongratulations! You have successfully enabled " + gen_https_names(dn) + "!", width=70)
            config.enable_mod("rewrite")
            if by_default():
                redirect_to_ssl(vhost, config)     
        else:
            logger.info("Congratulations! You have successfully enabled " + gen_https_names(dn) + "!")

    
    elif r.failure.IsInitialized():
        logger.fatal("Server reported failure.")
        sys.exit(1)

    else:
        logger.fatal("Unexpected server verification response!")
        sys.exit(43)


def redirect_to_ssl(vhost, config):
     for ssl_vh in vhost:
         success, redirect_vhost = config.redirect_all_ssl(ssl_vh)
         logger.info("\nRedirect vhost: " + redirect_vhost.file + " - " + str(success))
         # If successful, make sure redirect site is enabled
         if success:
             if not config.is_site_enabled(redirect_vhost.file):
                 config.enable_site(redirect_vhost)
                 logger.info("Enabling available site: " + redirect_vhost.file)

def renew(config):
    cert_key_pairs = config.get_all_certs_keys()
    for tup in cert_key_pairs:
        cert = M2Crypto.X509.load_cert(tup[0])
        issuer = cert.get_issuer()
        if recognized_ca(issuer):
            generate_renewal_req()

        # Wait for response, act accordingly
    gen_req_from_cert()

def authenticate():
    """
    Main call to do DV_SNI validation and deploy the trustify certificate
    TODO: This should be turned into a class...
    """
    global server, names, csr, privkey

    # Check if root
    if not os.geteuid()==0:
        sys.exit("\nOnly root can run trustify\n")

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
        logger.setLogger(logger.NcursesLogger())
        logger.setLogLevel(logger.INFO)
        #shower = progress_shower()
    else:
        logger.setLogger(sys.stdout)
        logger.setLogLevel(logger.INFO)

    # Check first if mod_ssl is loaded
    if not config.check_ssl_loaded():
        logger.info("Loading mod_ssl into Apache Server")
        config.enable_mod("ssl")

    req_file = csr
    key_file = privkey
    if csr and privkey:
        csr_pem = open(req_file).read().replace("\r", "")
        key_pem = open(key_file).read().replace("\r", "")
    if not csr or not privkey:
        # Generate new private key and corresponding csr!
        key_pem, csr_pem = make_key_and_csr(names, 2048)
        key_file, req_file = save_key_csr(key_pem, csr_pem)
        logger.info("Generating key: " + key_file)
        logger.info("Creating CSR: " + req_file)

    r, k = send_request(key_pem, csr_pem)


    challenges, dn = challenge_factory(r, os.path.abspath(req_file), os.path.abspath(key_file), config)

    # Find virtual hosts to deploy certificates too
    vhost = set()
    for name in dn:
        host = config.choose_virtual_host(name)
        if host is not None:
            vhost.add(host)

    for challenge in challenges:
        if not challenge.perform(quiet=curses):
            logger.fatal("challenge failed")
            sys.exit(1)
    logger.info("Configured Apache for challenge; waiting for verification...")

    logger.debug("waiting 3")
    time.sleep(3)

    r=decode(do(upstream, k))
    logger.debug(r)
    while r.challenge or r.proceed.IsInitialized():
        logger.debug("waiting 5")
        time.sleep(5)
        k.session = r.session
        r = decode(do(upstream, k))
        logger.debug(r)

    handle_verification_response(r, dn, challenges, vhost, key_file, config)
    

# vim: set expandtab tabstop=4 shiftwidth=4
