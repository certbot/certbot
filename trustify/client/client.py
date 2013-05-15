#!/usr/bin/env python

# I am attempting to clean up client.py by making it object oriented and
# adding proper better functions. The client should be able to be easily
# tested after the changes have been instituted.

import M2Crypto
# It is OK to use the upstream M2Crypto here instead of our modified
# version.
import urllib2
# XXX TODO: per https://docs.google.com/document/pub?id=1roBIeSJsYq3Ntpf6N0PIeeAAvu4ddn7mGo6Qb7aL7ew, urllib2 is unsafe (!) and must be replaced
import os, grp, pwd, sys, time, random, sys
import hashlib
import subprocess
# TODO: support a mode where use of interactive prompting is forbidden

from trustify.protocol.chocolate_pb2 import chocolatemessage
from trustify.client.sni_challenge import SNI_Challenge
from trustify.client.payment_challenge import Payment_Challenge
from trustify.client import configurator
from trustify.client import logger
from trustify.client.CONFIG import difficulty, cert_file, chain_file
from trustify.client.CONFIG import SERVER_ROOT, KEY_DIR, CERT_DIR

# it's weird to point to chocolate servers via raw IPv6 addresses, and such
# addresses can be %SCARY in some contexts, so out of paranoia let's disable
# them by default
allow_raw_ipv6_server = False
RSA_KEY_SIZE = 2048


class Client(object):
    # In case of import, dialog needs scope over the class
    dialog = None

    def __init__(self, ca_server, domains=[], cert_signing_request=None, private_key=None, use_curses=True):
        global dialog

        self.curses = use_curses
        if self.curses:
            import dialog

        # Logger needs to be initialized before Configurator
        self.init_logger()
        self.config = configurator.Configurator(SERVER_ROOT)

        self.server = ca_server
        if domains:
            self.names = domains
        else:
            self.names = self.get_all_names()
        self.csr_file = cert_signing_request
        self.key_file = private_key

        # If CSR is provided, the private key should also be provided.
        # TODO: Make sure key was actually used in CSR
        # TODO: Make sure key has proper permissions
        if self.csr_file and not self.key_file:
            logger.fatal("Please provide the private key file used in generating the provided CSR")
            sys.exit(1)

        self.sanity_check_names([ca_server] + domains)

        self.upstream = "https://%s/chocolate.py" % self.server

        

    def authenticate(self):
        # Display screen to select domains to validate
        self.names = self.filter_names(self.names)

        # Display choice of CA screen
        # TODO: Use correct server depending on CA
        choice = choice_of_ca()

        # Check first if mod_ssl is loaded
        if not config.check_ssl_loaded():
            logger.info("Loading mod_ssl into Apache Server")
            config.enable_mod("ssl")
        
        key_pem, csr_pem = self.get_key_csr_pem()
        
        r, k = self.send_request(key_pem, csr_pem, names)

        challenges = challenge_factory(r)

        # Find set of virtual hosts to deploy certificates to
        vhost = self.get_virtual_hosts(self.names)

        # Perform all "client knows first" challenges
        for challenge in challenges:
            if not challenge.perform(quiet=self.curses):
                # TODO: In this case the client should probably send a failure
                # to the server.
                logger.fatal("challenge failed")
                sys.exit(1)
        logger.info("Configured Apache for challenges; waiting for verification...")

        r = self.notify_server_of_completion(r)

        r = self.check_payment(r)

        self.handle_verification_response(r, challenges, vhost)

        return

    def handle_verification_response(self, r, challenges, vhost):
        if r.success.IsInitialized():
            # Allow Challenges to cleanup
            for chall in challenges:
                chall.cleanup()
            cert_chain_abspath = None
            cert_fd, cert_fn = unique_file(cert_file, 644)
            cert_fd.write(r.success.certificate)
            cert_fd.close()
            logger.info("Server issued certificate; certificate written to %s" % cert_fn)
            if r.success.chain:
                chain_fd, chain_fn = unique_file(chain_file, 644)
                chain_fd.write(r.success.chain)
                chain_fd.close()
 
                logger.info("Cert chain written to %s" % chain_fn)

                # This expects a valid chain file
                cert_chain_abspath = os.path.abspath(chain_fn)

            for host in vhost:
                self.config.deploy_cert(host, os.path.abspath(cert_fn), os.path.abspath(self.key_file), cert_chain_abspath)
                # Enable any vhost that was issued to, but not enabled
                if not host.enabled:
                    logger.info("Enabling Site " + host.file)
                    self.config.enable_site(host)

            # sites may have been enabled / final cleanup
            self.config.restart(quiet=self.curses)

            if self.curses:
                dialog.Dialog().msgbox("\nCongratulations! You have successfully enabled " + gen_https_names(self.names) + "!", width=70)
                self.config.enable_mod("rewrite")
                if by_default():
                    self.redirect_to_ssl(vhost)
                    self.config.restart(quiet=self.curses)     
            else:
                logger.info("Congratulations! You have successfully enabled " + gen_https_names(self.names) + "!")

        elif r.failure.IsInitialized():
            logger.fatal("Server reported failure.")
            sys.exit(1)

        else:
            logger.fatal("Unexpected server verification response!")
            sys.exit(43)

    def all_payment_challenge(r):
        if not r.challenge:
            return False
        for chall in r.challenge:
            if chall.type != r.Payment:
                return False

        return True

    def redirect_to_ssl(self, vhost):
        for ssl_vh in vhost:
         success, redirect_vhost = self.config.redirect_all_ssl(ssl_vh)
         logger.info("\nRedirect vhost: " + redirect_vhost.file + " - " + str(success))
         # If successful, make sure redirect site is enabled
         if success:
             if not self.config.is_site_enabled(redirect_vhost.file):
                 self.config.enable_site(redirect_vhost)
                 logger.info("Enabling available site: " + redirect_vhost.file)

    def check_payment(r):
        while r.challenge and all_payment_challenge(r):
            # dont need to change domain names here
            paymentChallenges, temp = challenge_factory(r)
            for chall in paymentChallenges:
                chall.perform(quiet=self.curses)

            logger.info("User has continued Trustify after submitting payment")
            proceed_msg = chocolatemessage()
            self.init_message(proceed_msg)
            proceed_msg.session = r.session
            proceed_msg.proceed.timestamp = int(time.time())
            proceed_msg.proceed.polldelay = 60
            # Send the proceed message
            # this used to be k?
            r = self.decode(self.do(self.upstream, proceed_msg))

        while r.proceed.IsInitialized():
            if r.proceed.IsInitialized():
                delay = min(r.proceed.polldelay, 60)
                logger.debug("waiting %d" % delay)
                time.sleep(delay)
                k.session = r.session
                # this used to be k?
                r = self.decode(self.do(self.upstream, proceed_msg))
                logger.debug(r)
        return r

    def notify_server_of_completion(self, r):
        did_it = chocolatemessage()
        self.init_message(did_it)
        did_it.session = r.session

        did_it.completedchallenge.extend(r.challenge)

        r=self.decode(self.do(self.upstream, did_it))

        logger.debug(r)
        delay = 5

        # TODO: Check this while statement
        while r.proceed.IsInitialized() or (r.challenge and not all_payment_challenge(r)):
            if r.proceed.IsInitialized():
                delay = min(r.proceed.polldelay, 60)
            logger.debug("waiting %d" % delay)
            time.sleep(delay)
            k.session = r.session
            r = self.decode(self.do(self.upstream, k))
            logger.debug(r)

        return r

    def get_virtual_hosts(self, domains):
        vhost = set()
        for name in domains:
            host = self.config.choose_virtual_host(name)
            if host is not None:
                vhost.add(host)
        return vhost

    def challenge_factory(self, r):
        sni_todo = []
        challenges = []
        logger.info("Received %s challenges from server." % len(r.challenge))
        for chall in r.challenge:
            logger.debug(chall)
            if chall.type == r.DomainValidateSNI:
                logger.info("\tDomainValidateSNI challenge for name %s." % chall.name)
                dvsni_nonce, dvsni_y, dvsni_ext = chall.data
                sni_todo.append( (chall.name, dvsni_y, dvsni_nonce, dvsni_ext) )
        
            if chall.type == r.Payment:
                url = chall.data[0]
                challenges.append(Payment_Challenge(url, "Alexa Top 10k Domain"))

        #if chall.type == r.Interactive:
        #    message = chall.data
        #    challenges.append(Interactive_Challenge(message)
        
        if sni_todo:
            # SNI_Challenge can satisfy many sni challenges at once so only 
            # one "challenge object" is issued for all sni_challenges
            challenges.append(SNI_Challenge(sni_todo, os.path.abspath(self.csr_file), os.path.abspath(self.key_file), self.config))
            logger.debug(sni_todo)

        return challenges

    def send_request(self, key_pem, csr_pem, names):
        k = chocolatemessage()
        m = chocolatemessage()
        self.init_message(k)
        self.init_message(m)
        logger.info("Creating request; generating hashcash...")
        self.make_request(m, csr_pem)
        self.sign_message(key_pem, m)
        logger.info("Created request; sending to server...")
        logger.debug(m)

        r = self.decode(self.do(self.upstream, m))
        logger.debug(r)
        while r.proceed.IsInitialized():
            if r.proceed.polldelay > 60: r.proceed.polldelay = 60
            logger.info("Waiting %d seconds..." % r.proceed.polldelay)
            time.sleep(r.proceed.polldelay)
            k.session = r.session
            r = self.decode(self.do(self.upstream, k))
            logger.debug(r)

        if r.failure.IsInitialized():
            logger.fatal("Chocolate Server reported failure.")
            sys.exit(1)
        
        return r, k

    def make_request(self, m, csr_pem):
        m.request.recipient = server
        m.request.timestamp = int(time.time())
        m.request.csr = csr_pem
        hashcash_cmd = ["hashcash", "-P", "-m", "-z", "12", "-b", `difficulty`, "-r", server]
        if quiet:
            hashcash = subprocess.Popen(hashcash_cmd, preexec_fn=drop_privs, shell= False, stdout=subprocess.PIPE, stderr=open("/dev/null", "w")).communicate()[0].rstrip()
        else:
            hashcash = subprocess.Popen(hashcash_cmd, preexec_fn=drop_privs, shell= False, stdout=subprocess.PIPE).communicate()[0].rstrip()

        if hashcash: m.request.clientpuzzle = hashcash

    def get_key_csr_pem(self):
        """
        Returns key and CSR in pem form, using provided files or generating a new files if 
        necessary
        """
        key_pem = None
        csr_pem = None
        if not self.key_file:
            key_pem = make_key(RSA_KEY_SIZE)
            # Save file
            if not os.path.isdir(KEY_DIR):
                os.makedirs(KEY_DIR, 0700)
            key_f, self.key_file = self.unique_file(KEY_DIR + "key-trustify.pem", 0600)
            key_f.write(key_pem)
            key_f.close()
        else:
            try:
                key_pem = open(self.key_file).read().replace("\r", "")
            except:
                logger.fatal("Unable to open key file: %s" % self.key_file)
                sys.exit(1)

        if not self.csr_file:
            csr_pem = make_csr(self.names)
            # Save CSR
            if not os.path.isdir(CERT_DIR):
                os.makedirs(CERT_DIR, 0755)
            csr_f, self.csr_file = unique_file(CERT_DIR + "csr-trustify.pem", 0644)
            csr_f.write(csr)
            csr_f.close()
        else:
            try:
                csr_pem = open(self.csr_file).read().replace("\r", "")
            except:
                logger.fatal("Unable to open CSR file: %s" % self.csr_file)
                sys.exit(1)

        return key_pem, csr_pem


    # based on M2Crypto unit test written by Toby Allsopp
    from M2Crypto import EVP, X509, RSA

    def make_key(self, bits=RSA_KEY_SIZE):
        """
        Returns new RSA key in PEM form with specified bits
        """
        rsa = RSA.gen_key(bits, 65537)
        key_pem = rsa.as_pem(cipher=None)
        rsa = None # should not be freed here

        return key_pem
        
    def make_csr(self, domains):
        """
        Returns new CSR in PEM form using self.key_file containing all domains
        """
        assert domains, "Must provide one or more hostnames for the CSR."
        rsa_key = M2Crypto.RSA.load_key(self.key_file)
        pk = EVP.PKey()
        pk.assign_rsa(rsa_key)

        x = X509.Request()
        x.set_pubkey(pk)
        name = x.get_subject()
        name.CN = domains[0]
        for d in domains:
            ext = X509.new_extension('subjectAltName', 'DNS:%s' % d)
            extstack.push(ext)
        x.add_extensions(extstack)
        x.sign(pk,'sha1')
        assert x.verify(pk)
        pk2 = x.get_pubkey()
        assert x.verify(pk2)
        return x.as_pem()

    def __rsa_sign(self, key, data):
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

    def do(self, upstream, m):
        u = urllib2.urlopen(upstream, m.SerializeToString())
        return u.read()

    def decode(self, m):
        return (chocolatemessage.FromString(m))

    def init_message(self, m):
        m.chocolateversion = 1
        m.session = ""

    def sign_message(self, key, m):
        m.request.sig = __rsa_sign(key, ("(%d) (%s) (%s)" % (m.request.timestamp, m.request.recipient, m.request.csr)))
        
    def filter_names(self, names):
        d = dialog.Dialog()
        choices = [(n, "", 1) for n in names]
        result = d.checklist("Which names would you like to activate HTTPS for?", choices=choices)
        if result[0] != 0 or not result[1]:
            sys.exit(1)
        return result[1]

    def choice_of_ca(self):
        d = dialog.Dialog()
        choices = get_cas()

        result = d.menu("Pick a Certificate Authority.  They're all unique and special!", width=70, choices=choices)

        if result[0] != 0:
            sys.exit(1)

        return result

    def get_cas():
        DV_choices = []
        OV_choices = []
        EV_choices = []
        choices = []
        try:
            with open("/etc/trustify/.ca_offerings") as f:
                for line in f:
                    choice = line.split(";", 1)
                    if 'DV' in choice[0]:
                        DV_choices.append(choice)
                    elif 'OV' in choice[0]:
                        OV_choices.append(choice)
                    else:
                        EV_choices.append(choice)

                random.shuffle(DV_choices)
                random.shuffle(OV_choices)
                random.shuffle(EV_choices)
                choices = DV_choices + OV_choices + EV_choices
            #choices = [line.split(";", 1) for line in f]                       
        except IOError as e:
            logger.fatal("Unable to find .ca_offerings file")
            sys.exit(1)

        return choices

    def get_all_names(self):
	self.names = config.get_all_names()
        
        if not self.names:
            logger.fatal("No domain names were found in your apache config")
            logger.fatal("Either specify which names you would like trustify to validate or add server names to your virtual hosts")
            sys.exit(1)
        
        
    def init_logger(self):
        if self.curses:
            logger.setLogger(logger.NcursesLogger())
            logger.setLogLevel(logger.INFO)
        else:
            logger.setLogger(sys.stdout)
            logger.setLogLevel(logger.INFO)

    def sanity_check_names(self, names):
        for name in names:
            assert self.is_hostname_sane(name), `name` + " is an impossible hostname"

    def is_hostname_sane(self, hostname):
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

    def gen_https_names(self, domains):
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

        if domains:
            result = result + "https://" + domains[len(domains)-1]
        return result

    def by_default(self):
        d = dialog.Dialog()
        choices = [("Easy", "Allow both HTTP and HTTPS access to these sites"), ("Secure", "Make all requests redirect to secure HTTPS access")]
        result = d.menu("Please choose whether HTTPS access is required or optional.", width=70, choices=choices)
        if result[0] != 0:
            sys.exit(1)
        return result[1] == "Secure"

def sha256(m):
    return hashlib.sha256(m).hexdigest()


# based on M2Crypto unit test written by Toby Allsopp
#from M2Crypto import EVP, X509, RSA

# def make_key_and_csr(names, bits=2048):
#     """Return a tuple (key, csr) containing a PEM-formatted private key
#     of the specified number of bits and a CSR requesting a certificate for
#     the specified DNS names."""
#     assert names, "Must provide one or more hostnames."
#     pk = EVP.PKey()
#     x = X509.Request()
#     rsa = RSA.gen_key(bits, 65537)
#     pk.assign_rsa(rsa)
#     key_pem = rsa.as_pem(cipher=None)
#     rsa = None # should not be freed here
#     x.set_pubkey(pk)
#     name = x.get_subject()
#     name.CN = names[0]
#     extstack = X509.X509_Extension_Stack()
#     for n in names:
#         ext = X509.new_extension('subjectAltName', 'DNS:%s' % n)
#         extstack.push(ext)
#     x.add_extensions(extstack)
#     x.sign(pk,'sha1')
#     assert x.verify(pk)
#     pk2 = x.get_pubkey()
#     assert x.verify(pk2)
#     return key_pem, x.as_pem()

# def by_default():
#     d = dialog.Dialog()
#     choices = [("Easy", "Allow both HTTP and HTTPS access to these sites"), ("Secure", "Make all requests redirect to secure HTTPS access")]
#     result = d.menu("Please choose whether HTTPS access is required or optional.", width=70, choices=choices)
#     if result[0] != 0:
#         sys.exit(1)
#     return result[1] == "Secure"


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

# def make_request(server, m, csr, names, quiet=False):
#     m.request.recipient = server
#     m.request.timestamp = int(time.time())
#     m.request.csr = csr
#     hashcash_cmd = ["hashcash", "-P", "-m", "-z", "12", "-b", `difficulty`, "-r", server]
#     if quiet:
#         hashcash = subprocess.Popen(hashcash_cmd, preexec_fn=drop_privs, shell= False, stdout=subprocess.PIPE, stderr=open("/dev/null", "w")).communicate()[0].rstrip()
#     else:
#         hashcash = subprocess.Popen(hashcash_cmd, preexec_fn=drop_privs, shell= False, stdout=subprocess.PIPE).communicate()[0].rstrip()

#     if hashcash: m.request.clientpuzzle = hashcash

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

# def save_key_csr(key, csr):
#     """
#     This function saves the newly generated key and csr to new files
#     in the ssl and certs directories respectively
#     This function sets the appropriate permissions for the key and its
#     directory.
#     """
#     # Create directories if they do not exist
#     # This should probably go in the installation script
#     # Make sure directories exist & make sure directories are set with the
#     # correct permissions if they do exist.
#     # Note: Appears I forgot to check existing directories permissions
#     if not os.path.isdir(CERT_DIR):
#         os.makedirs(CERT_DIR, 0755)
#     if not os.path.isdir(KEY_DIR):
#         os.makedirs(KEY_DIR, 0700)

#     # Write key to new file and change permissions
#     key_f, key_fn = unique_file(KEY_DIR + "key-trustify.pem", 0600)
#     key_f.write(key)
#     key_f.close()
#     # Write CSR to new file
#     csr_f, csr_fn = unique_file(CERT_DIR + "csr-trustify.pem", 0644)
#     csr_f.write(csr)
#     csr_f.close()
        
#     return key_fn, csr_fn

def recognized_ca(issuer):
    pass

def gen_req_from_cert():
    return

# def unique_file(default_name, mode = 0777):
#     """
#     Safely finds a unique file for writing only (by default)
#     """
#     count = 1
#     f_parsed = os.path.splitext(default_name)
#     while 1:
#         try:
#             fd = os.open(default_name, os.O_CREAT|os.O_EXCL|os.O_RDWR, mode)
#             return os.fdopen(fd, 'w'), default_name
#         except OSError:
#             pass
#         default_name = f_parsed[0] + '_' + str(count) + f_parsed[1]
#         count += 1

# def gen_https_names(domains):
#     """
#     Returns a string of the domains formatted nicely with https:// prepended
#     to each
#     """
#     result = ""
#     if len(domains) > 2:
#         for i in range(len(domains)-1):
#             result = result + "https://" + domains[i] + ", "
#         result = result + "and "
#     if len(domains) == 2:
#         return "https://" + domains[0] + " and https://" + domains[1]

#     if domains:
#         result = result + "https://" + domains[len(domains)-1]
#     return result

# def challenge_factory(r, req_filepath, key_filepath, config):
#     sni_todo = []
#     dn = []
#     challenges = []
#     logger.info("Received %s challenges from server." % len(r.challenge))
#     for chall in r.challenge:
#         logger.debug(chall)
#         if chall.type == r.DomainValidateSNI:
#             logger.info("\tDomainValidateSNI challenge for name %s." % chall.name)
#             dvsni_nonce, dvsni_y, dvsni_ext = chall.data
#             sni_todo.append( (chall.name, dvsni_y, dvsni_nonce, dvsni_ext) )
            
#             # TODO: This domain name list is inelegant and the info should be 
#             # gathered from the challenge list itself
#             dn.append(chall.name)

#         if chall.type == r.Payment:
#             url = chall.data[0]
#             challenges.append(Payment_Challenge(url, "Alexa Top 10k Domain"))

#         #if chall.type == r.Interactive:
#         #    message = chall.data
#         #    challenges.append(Interactive_Challenge(message)
        
#     if sni_todo:
#         # SNI_Challenge can satisfy many sni challenges at once so only 
#         # one "challenge object" is issued for all sni_challenges
#         challenges.append(SNI_Challenge(sni_todo, req_filepath, key_filepath, config))
#         logger.debug(sni_todo)

#     return challenges, dn
        

# def send_request(key_pem, csr_pem, names, quiet=curses):
#     '''
#     Sends the request to the CA and returns a response
#     '''
#     global server
#     upstream = "https://%s/chocolate.py" % server
#     k=chocolatemessage()
#     m=chocolatemessage()
#     init(k)
#     init(m)
#     logger.info("Creating request; generating hashcash...")
#     make_request(server, m, csr_pem, names, quiet=curses)
#     sign(key_pem, m)
#     logger.info("Created request; sending to server...")
#     logger.debug(m)

#     r=decode(do(upstream, m))
#     logger.debug(r)
#     while r.proceed.IsInitialized():
#        if r.proceed.polldelay > 60: r.proceed.polldelay = 60
#        logger.info("Waiting %d seconds..." % r.proceed.polldelay)
#        time.sleep(r.proceed.polldelay)
#        k.session = r.session
#        r = decode(do(upstream, k))
#        logger.debug(r)

#     if r.failure.IsInitialized():
#         logger.fatal("Chocolate Server reported failure.")
#         sys.exit(1)
        
#     return r, k


# def handle_verification_response(r, dn, challenges, vhost, key_file, config):
#     if r.success.IsInitialized():
#         for chall in challenges:
#             chall.cleanup()
#         cert_chain_abspath = None
#         cert_fd, cert_fn = unique_file(cert_file, 644)
#         cert_fd.write(r.success.certificate)
#         cert_fd.close()
#         logger.info("Server issued certificate; certificate written to %s" % cert_fn)
#         if r.success.chain:
#             chain_fd, chain_fn = unique_file(chain_file, 644)
#             chain_fd.write(r.success.chain)
#             chain_fd.close()
 
#             logger.info("Cert chain written to %s" % chain_fn)

#             # This expects a valid chain file
#             cert_chain_abspath = os.path.abspath(chain_fn)

#         for host in vhost:
#             config.deploy_cert(host, os.path.abspath(cert_fn), os.path.abspath(key_file), cert_chain_abspath)
#             # Enable any vhost that was issued to, but not enabled
#             if not host.enabled:
#                 logger.info("Enabling Site " + host.file)
#                 config.enable_site(host)

#         # sites may have been enabled / final cleanup
#         config.restart(quiet=curses)

#         if curses:
#             dialog.Dialog().msgbox("\nCongratulations! You have successfully enabled " + gen_https_names(dn) + "!", width=70)
#             config.enable_mod("rewrite")
#             if by_default():
#                 redirect_to_ssl(vhost, config)
#                 config.restart(quiet=curses)     
#         else:
#             logger.info("Congratulations! You have successfully enabled " + gen_https_names(dn) + "!")

#     elif r.failure.IsInitialized():
#         logger.fatal("Server reported failure.")
#         sys.exit(1)

#     else:
#         logger.fatal("Unexpected server verification response!")
#         sys.exit(43)


# def redirect_to_ssl(vhost, config):
#      for ssl_vh in vhost:
#          success, redirect_vhost = config.redirect_all_ssl(ssl_vh)
#          logger.info("\nRedirect vhost: " + redirect_vhost.file + " - " + str(success))
#          # If successful, make sure redirect site is enabled
#          if success:
#              if not config.is_site_enabled(redirect_vhost.file):
#                  config.enable_site(redirect_vhost)
#                  logger.info("Enabling available site: " + redirect_vhost.file)

def renew(config):
    cert_key_pairs = config.get_all_certs_keys()
    for tup in cert_key_pairs:
        cert = M2Crypto.X509.load_cert(tup[0])
        issuer = cert.get_issuer()
        if recognized_ca(issuer):
            generate_renewal_req()

        # Wait for response, act accordingly
    gen_req_from_cert()

# def all_payment_challenge(r):
#     if not r.challenge:
#         return False
#     for chall in r.challenge:
#         if chall.type != r.Payment:
#             return False

#     return True

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


    if curses:
        logger.setLogger(logger.NcursesLogger())
        logger.setLogLevel(logger.INFO)
    else:
        logger.setLogger(sys.stdout)
        logger.setLogLevel(logger.INFO)
        
    # Logger should be init before config
    config = configurator.Configurator()

    if not names:
	names = config.get_all_names()

    if curses:
        if not names:
            logger.fatal("No domain names were found in your apache config")
            logger.fatal("Either specify which names you would like trustify to validate or add server names to your virtual hosts")
            sys.exit(1)

        names = filter_names(names)
        choice = choice_of_ca()
        if choice[0] != 0:
            sys.exit(1)


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

    r, k = send_request(key_pem, csr_pem, names)


    challenges, dn = challenge_factory(r, os.path.abspath(req_file), os.path.abspath(key_file), config)

    # Find set of virtual hosts to deploy certificates to
    vhost = set()
    for name in dn:
        host = config.choose_virtual_host(name)
        if host is not None:
            vhost.add(host)

    for challenge in challenges:
        if not challenge.perform(quiet=curses):
            # TODO: In this case the client should probably send a failure
            # to the server.
            logger.fatal("challenge failed")
            sys.exit(1)
    logger.info("Configured Apache for challenge; waiting for verification...")

    #############################################################
    # This whole bottom section should be reworked once the protocol
    # is finalized... it is currently quite ugly
    ############################################################

    did_it = chocolatemessage()
    init(did_it)
    did_it.session = r.session
    # This will blindly assert that all of the challenges have been
    # complied with, by simply copying them from the challenge data
    # structure into a new completedchallenge structure.  This is
    # kind of crude, because the client could instead actually build up
    # a completedchallenge structure piece-by-piece as it actually
    # complies with challenges (and then send that structure for the
    # server to look at).  In the existing client, completedchallenge
    # is only ever sent once _all_ of the (assumed to be dvsni)
    # challenges have been met, and client-side failure to meet any
    # challenge is immediately fatal to the client.  In the existing
    # server, the client's assertion that the client has met any
    # (assumed to be dvsni) challenge(s) will result in the server
    # scheduling a test of all challenges.
    did_it.completedchallenge.extend(r.challenge)

    r=decode(do(upstream, did_it))
    logger.debug(r)
    delay = 5
    #while r.challenge or r.proceed.IsInitialized():
    while r.proceed.IsInitialized() or (r.challenge and not all_payment_challenge(r)):
        if r.proceed.IsInitialized():
            delay = min(r.proceed.polldelay, 60)
        logger.debug("waiting %d" % delay)
        time.sleep(delay)
        k.session = r.session
        r = decode(do(upstream, k))
        logger.debug(r)

    # This should be invoked if a payment is necessary
    # This is being tested and will have to be cleaned and organized 
    # once the protocol is finalized.
    while r.challenge and all_payment_challenge(r):
        # dont need to change domain names here
        paymentChallenges, temp = challenge_factory(r, os.path.abspath(req_file), os.path.abspath(key_file), config)
        for chall in paymentChallenges:
            chall.perform(quiet=curses)

        logger.info("User has continued Trustify after submitting payment")
        proceed_msg = chocolatemessage()
        init(proceed_msg)
        proceed_msg.session = r.session
        proceed_msg.proceed.timestamp = int(time.time())
        proceed_msg.proceed.polldelay = 60
        # Send the proceed message
        r = decode(do(upstream, k))

        while r.proceed.IsInitialized():
            if r.proceed.IsInitialized():
                delay = min(r.proceed.polldelay, 60)
                logger.debug("waiting %d" % delay)
                time.sleep(delay)
                k.session = r.session
                r = decode(do(upstream, k))
                logger.debug(r)

    handle_verification_response(r, dn, challenges, vhost, key_file, config)
    

# vim: set expandtab tabstop=4 shiftwidth=4
