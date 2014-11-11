#!/usr/bin/env python

import M2Crypto
# It is OK to use the upstream M2Crypto here instead of our modified
# version.
import urllib2, json
# XXX TODO: per https://docs.google.com/document/pub?id=1roBIeSJsYq3Ntpf6N0PIeeAAvu4ddn7mGo6Qb7aL7ew, urllib2 is unsafe (!) and must be replaced
import os, grp, pwd, sys, time, random, sys, shutil
import jose, csv
import subprocess
from M2Crypto import EVP, X509, RSA
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

from trustify.client.acme import acme_object_validate
from trustify.client.sni_challenge import SNI_Challenge
from trustify.client.payment_challenge import Payment_Challenge
from trustify.client import configurator
from trustify.client import logger, display
from trustify.client import trustify_util, crypto_util, display
from trustify.client.CONFIG import NONCE_SIZE, RSA_KEY_SIZE, CERT_PATH, CHAIN_PATH
from trustify.client.CONFIG import SERVER_ROOT, KEY_DIR, CERT_DIR, CERT_KEY_BACKUP
from trustify.client.CONFIG import CHALLENGE_PREFERENCES, EXCLUSIVE_CHALLENGES
# it's weird to point to chocolate servers via raw IPv6 addresses, and such
# addresses can be %SCARY in some contexts, so out of paranoia let's disable
# them by default
allow_raw_ipv6_server = False

class Client(object):
    # In case of import, dialog needs scope over the class
    dialog = None
    
    def __init__(self, ca_server, domains=[], cert_signing_request=None, private_key=None, use_curses=True):
        global dialog

        self.curses = use_curses
        if self.curses:
            import dialog
            self.d = dialog.Dialog()
            

        # Logger needs to be initialized before Configurator
        self.init_logger()
        self.config = configurator.Configurator(SERVER_ROOT)

        self.server = ca_server
        if domains:
            self.names = domains
        else:
            # This function adds all names 
            # found within the config to self.names
            self.get_all_names()
        self.csr_file = cert_signing_request
        self.key_file = private_key

        # If CSR is provided, the private key should also be provided.
        # TODO: Make sure key was actually used in CSR
        # TODO: Make sure key has proper permissions
        if self.csr_file and not self.key_file:
            logger.fatal("Please provide the private key file used in generating the provided CSR")
            sys.exit(1)

        self.sanity_check_names([ca_server] + domains)

        self.server_url = "https://%s/acme/" % self.server

        

    def authenticate(self):
        # Check configuration
        if not self.config.configtest():
            sys.exit(1)

        # Display screen to select domains to validate
        self.names = self.filter_names(self.names)
        self.names = [self.names[0]]

        # Display choice of CA screen
        # TODO: Use correct server depending on CA
        choice = self.choice_of_ca()

        # Check first if mod_ssl is loaded
        if not self.config.check_ssl_loaded():
            logger.info("Loading mod_ssl into Apache Server")
            self.config.enable_mod("ssl")


        key_pem, csr_der = self.get_key_csr_pem()

        challenge_dict = self.send(self.challenge_request(self.names))
        
        challenge_dict = self.is_expected_msg(challenge_dict, "challenge")


        #Perform Challenges
        responses, challenge_objs = self.verify_identity(challenge_dict)

        # Find set of virtual hosts to deploy certificates to
        vhost = self.get_virtual_hosts(self.names)

        authorization_dict = self.send(self.authorization_request(challenge_dict["sessionID"], self.names[0], challenge_dict["nonce"], responses))

        authorization_dict = self.is_expected_msg(authorization_dict, "authorization")
        if not authorization_dict:
            self.cleanup_challenges(challenge_objs)
            logger.fatal("Failed Authorization procedure - cleaning up challenges")
            sys.exit(1)
        
        certificate_dict = self.send(self.certificate_request(csr_der, self.key_file))
        
        certificate_dict = self.is_expected_msg(certificate_dict, "certificate")

        # Install Certificate
        self.cleanup_challenges(challenge_objs)
        self.install_certificate(certificate_dict, vhost)
        
        # Perform optimal config changes
        self.optimize_config(vhost)

        self.config.save("Completed Augeas Authentication")

        self.store_cert_key(False)

        return


    def revoke(self, c):
        x = M2Crypto.X509.load_cert(c["backup_cert_file"])
        cert_der = x.as_der()

        #self.find_key_for_cert()
        revocation_dict = self.send(self.revocation_request(c["backup_key_file"], cert_der))

        revocation_dict = self.is_expected_msg(revocation_dict, "revocation")

        self.d.msgbox("You have successfully revoked the certificate for %s" % c["cn"], width=70, height=16)

        self.remove_cert_key(c)
        sys.exit(0)

    def remove_cert_key(self, c):
        list_file = CERT_KEY_BACKUP + "LIST"
        list_file2 = CERT_KEY_BACKUP + "LIST.tmp"
        with open(list_file, 'rb') as orgfile:
            csvreader = csv.reader(orgfile)
            with open(list_file2, 'wb') as newfile:
                csvwriter = csv.writer(newfile)
                for row in csvreader:
                    if not (row[0] == str(c["idx"]) and row[1] == c["orig_cert_file"] and row[2] == c["orig_key_file"]):
                        csvwriter.writerow(row)
                        

        # remember that these are
        shutil.copy2(list_file2, list_file)
        os.remove(list_file2)
        os.remove(c['backup_cert_file'])
        os.remove(c['backup_key_file'])
    
    def store_revocation_token(self, token):
        return

    
        
    def store_cert_key(self, encrypt = False):
        list_file = CERT_KEY_BACKUP + "LIST"
        trustify_util.make_or_verify_dir(CERT_KEY_BACKUP, 0700)
        idx = 0

        if encrypt:
            logger.error("Unfortunately securely storing the certificates/keys is not yet available. Stay tuned for the next update!")
            return False
        else:
            if os.path.isfile(list_file):
                with open(list_file, 'r+b') as csvfile:
                    csvreader = csv.reader(csvfile)
                    for r in csvreader:
                        idx = int(r[0]) + 1
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow([str(idx), self.cert_file, self.key_file])

            else:
                with open(list_file, 'wb') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow(["0", self.cert_file, self.key_file])

            shutil.copy2(self.key_file, CERT_KEY_BACKUP + os.path.basename(self.key_file) + "_" + str(idx))
            shutil.copy2(self.cert_file, CERT_KEY_BACKUP + os.path.basename(self.cert_file) + "_" + str(idx))

    def list_certs_keys(self):
        list_file = CERT_KEY_BACKUP + "LIST"
        certs = []

        if not os.path.isfile(CERT_KEY_BACKUP + "LIST"):
            logger.info("You don't have any certificates saved from trustify")
            return
        
        with open(list_file, 'rb') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                c = crypto_util.get_cert_info(row[1])
                c["orig_key_file"] = row[2]
                c["orig_cert_file"] = row[1]
                c["backup_key_file"] = CERT_KEY_BACKUP + os.path.basename(row[2]) + "_" + row[0]
                c["backup_cert_file"] = CERT_KEY_BACKUP + os.path.basename(row[1]) + "_" + row[0]
                c["idx"] = int(row[0])
                certs.append(c)
        if certs:
            self.__display_certs(certs)
        else:
            logger.info("There are not any trusted Let's Encrypt certificates for this server.")

    def __display_certs(self, certs):
        while True:
            menu_choices = [(str(i+1), str(c["cn"]) + " - " + c["pub_key"] + " - " + str(c["not_before"])[:-6]) for i, c in enumerate(certs)]
            if self.curses:
                code, selection = self.d.menu("Which certificate would you like to revoke?", choices = menu_choices, 
                                              help_button=True, help_label="More Info", ok_label="Revoke", 
                                              width=70, height=16)


                if code == self.d.DIALOG_OK:
                    if display.confirm_revocation(certs[int(selection)-1]):
                        self.revoke(c)
                    
                elif code == self.d.DIALOG_CANCEL:
                    exit(0)
                elif code == "help":
                    display.more_info_cert(certs[int(selection)-1])
                
                    
        
    def revocation_request(self, key_file, cert_der):
        return {"type":"revocationRequest", "certificate":jose.b64encode_url(cert_der), "signature":crypto_util.create_sig(cert_der, key_file)}

    
    def install_certificate(self, certificate_dict, vhost):
        cert_chain_abspath = None
        cert_fd, self.cert_file = trustify_util.unique_file(CERT_PATH, 644)
        cert_fd.write(crypto_util.convert_b64_cert_to_pem(certificate_dict["certificate"]))
        cert_fd.close()
        logger.info("Server issued certificate; certificate written to %s" % self.cert_file)
        if certificate_dict.get("chain", None):
            chain_fd, chain_fn = trustify_util.unique_file(CHAIN_PATH, 644)
            for c in certificate_dict.get("chain", []):
                chain_fd.write(crypto_util.convert_b64_cert_to_pem(c))
            chain_fd.close()
            
            logger.info("Cert chain written to %s" % chain_fn)
            
            # This expects a valid chain file
            cert_chain_abspath = os.path.abspath(chain_fn)

        for host in vhost:
            self.config.deploy_cert(host, os.path.abspath(self.cert_file), os.path.abspath(self.key_file), cert_chain_abspath)
            # Enable any vhost that was issued to, but not enabled
            if not host.enabled:
                logger.info("Enabling Site " + host.file)
                self.config.enable_site(host)

        # sites may have been enabled / final cleanup
        self.config.restart(quiet=self.curses)

        display.success_installation(self.names)


    def optimize_config(self, vhost):
        if display.redirect_by_default():
            self.config.enable_mod("rewrite")
            self.redirect_to_ssl(vhost)
            self.config.restart(quiet=self.curses)

    def certificate_request(self, csr_der, key):
        logger.info("Preparing and sending CSR..")
        return {"type":"certificateRequest", "csr":jose.b64encode_url(csr_der), "signature":crypto_util.create_sig(csr_der, self.key_file)}

    def cleanup_challenges(self, challenge_objs):
        logger.info("Cleaning up challenges...")
        for c in challenge_objs:
            c.cleanup()

    def is_expected_msg(self, msg_dict, expected, delay=3, rounds = 20):
        for i in range(rounds):
            if msg_dict["type"] == expected:
                return msg_dict
            elif msg_dict["type"] == "error":
                logger.error("%s: %s - More Info: %s" % (msg_dict["error"], msg_dict.get("message", ""), msg_dict.get("moreInfo", "")))
                return None
            elif msg_dict["type"] == "defer":
                logger.info("Waiting for %d seconds..." % delay)
                time.sleep(delay)
                msg_dict = self.send(self.status_request(msg_dict["token"]))
            else:
                logger.fatal("Received unexpected message")
                logger.fatal("Expected: %s" % expected)
                logger.fatal("Received: " + msg_dict)
                sys.exit(33)

        logger.error("Server has deferred past the max of %d seconds" % (rounds * delay))
        return None
        

    def authorization_request(self, id, name, server_nonce, responses):
        auth_req = {"type":"authorizationRequest", "sessionID":id, "nonce":server_nonce}
        auth_req["signature"] = crypto_util.create_sig(name + jose.b64decode_url(server_nonce), self.key_file)
        auth_req["responses"] = responses
        return auth_req

    def status_request(self, token):
        return {"type":"statusRequest", "token":token}
    
    def challenge_request(self, names):
        #logger.info("Temporarily only enabling one name")
        return {"type":"challengeRequest", "identifier": names[0]}

    def verify_identity(self, c):
        path = self.gen_challenge_path(c["challenges"], c.get("combinations", None))
        logger.info("Peforming the following challenges:")
                        
        # Every indicies element is a list of integers referring to which challenges in the master list
        # the challenge object satisfies
        # Single Challenge objects that can satisfy multiple server challenges
        # mess up the order of the challenges, thus requiring the indicies
        challenge_objs, indicies = self.challenge_factory(self.names[0], c["challenges"], path)


        responses = [None] * len(c["challenges"])

        # Perform challenges and populate responses
        for i, c_obj in enumerate(challenge_objs):
            if not c_obj.perform():
                logger.fatal("Challenge Failed")
                sys.exit(1)
            for index in indicies[i]:
                responses[index] = c_obj.generate_response()

        logger.info("Configured Apache for challenges; waiting for verification...")
            
        return responses, challenge_objs
            
    def gen_challenge_path(self, challenges, combos):
        if combos:
            return self.__find_smart_path(challenges, combos)

        return self.__find_dumb_path(challenges)
        
    def __find_smart_path(self, challenges, combos):
        """
        Can be called if combinations  is included
        Function uses a simple ranking system to choose the combo with the lowest cost
        """
        chall_cost = {}
        max_cost = 0
        for i, chall in enumerate(CHALLENGE_PREFERENCES):
            chall_cost[chall] = i
            max_cost += i

        best_combo = []
        # Set above completing all of the available challenges
        best_combo_cost = max_cost + 1
        
        combo_total = 0
        for combo in combos:
            for c in combo:
                combo_total += chall_cost.get(challenges[c]["type"], max_cost)
            if combo_total < best_combo_total:
                best_combo = combo
            combo_total = 0

        if not best_combo:
            logger.fatal("Client does not support any combination of challenges to satisfy ACME server")
            sys.exit(22)

        return best_combo

    def __find_dumb_path(self, challenges):
        """
        Should be called if the combinations hint is not included by the server
        This function returns the best path that does not contain multiple mutually exclusive
        challenges
        """
        # Add logic for a crappy server
        # Choose a DV
        path = []
        for pref_c in CHALLENGE_PREFERENCES:
            for i, offered_c in enumerate(challenges):
                if pref_c == offered_c["type"] and self.is_preferred(offered_c["type"], path):
                    path.append((i, offered_c["type"]))

        return [tup[0] for tup in path]


    def is_preferred(self, offered_c_type, path):
        for tup in path:
            for s in EXCLUSIVE_CHALLENGES:
                # Second part is in case we eventually allow multiple names to be challenged
                # at the same time
                if (tup[1] in s and offered_c_type in s) and tup[1] != offered_c_type:
                    return False

        return True

    def send(self, json_obj):
        acme_object_validate(json.dumps(json_obj))
        response = urllib2.urlopen(self.server_url, json.dumps(json_obj)).read()
        acme_object_validate(response)
        return json.loads(response)


    def redirect_to_ssl(self, vhost):
        for ssl_vh in vhost:
         success, redirect_vhost = self.config.redirect_all_ssl(ssl_vh)
         logger.info("\nRedirect vhost: " + redirect_vhost.file + " - " + str(success))
         # If successful, make sure redirect site is enabled
         if success:
             if not self.config.is_site_enabled(redirect_vhost.file):
                 self.config.enable_site(redirect_vhost)
                 logger.info("Enabling available site: " + redirect_vhost.file)

    
    def get_virtual_hosts(self, domains):
        vhost = set()
        for name in domains:
            host = self.config.choose_virtual_host(name)
            if host is not None:
                vhost.add(host)
        return vhost

    def challenge_factory(self, name, challenges, path):
        sni_todo = []
        # Since a single invocation of SNI challenge can satsify multiple challenges
        # We must keep track of all the challenges it satisfies
        sni_satisfies = []

        challenge_objs = []
        challenge_obj_indicies = []
        for c in path:
            if challenges[c]["type"] == "dvsni":
                logger.info("\tDomainValidateSNI challenge for name %s." % name)
                sni_satisfies.append(c)
                sni_todo.append( (str(name), str(challenges[c]["r"]), str(challenges[c]["nonce"])) )
        
            elif challenges[c]["type"] == "recoveryToken":
                logger.fatal("RecoveryToken Challenge type not currently supported")
                sys.exit(82)

            else:
                logger.fatal("Challenge not currently supported")
                sys.exit(82)
        
        if sni_todo:
            # SNI_Challenge can satisfy many sni challenges at once so only 
            # one "challenge object" is issued for all sni_challenges
            challenge_objs.append(SNI_Challenge(sni_todo, os.path.abspath(self.key_file), self.config))
            challenge_obj_indicies.append(sni_satisfies)
            logger.debug(sni_todo)

        return challenge_objs, challenge_obj_indicies


    def get_key_csr_pem(self, csr_return_format = 'der'):
        """
        Returns key and CSR using provided files or generating new files if necessary.
        Both will be saved in pem format on the filesystem. The CSR can 
        optionally be returned in DER format as the CSR cannot be loaded back into
        M2Crypto.
        """
        key_pem = None
        csr_pem = None
        if not self.key_file:
            key_pem = crypto_util.make_key(RSA_KEY_SIZE)
            # Save file
            trustify_util.make_or_verify_dir(KEY_DIR, 0700)
            key_f, self.key_file = trustify_util.unique_file(KEY_DIR + "key-trustify.pem", 0600)
            key_f.write(key_pem)
            key_f.close()
            logger.info("Generating key: %s" % self.key_file)
        else:
            try:
                key_pem = open(self.key_file).read().replace("\r", "")
            except:
                logger.fatal("Unable to open key file: %s" % self.key_file)
                sys.exit(1)

        if not self.csr_file:
            csr_pem, csr_der = crypto_util.make_csr(self.key_file, self.names)
            # Save CSR
            trustify_util.make_or_verify_dir(CERT_DIR, 0755)
            csr_f, self.csr_file = trustify_util.unique_file(CERT_DIR + "csr-trustify.pem", 0644)
            csr_f.write(csr_pem)
            csr_f.close()
            logger.info("Creating CSR: %s" % self.csr_file)
        else:
            #TODO fix this der situation
            try:
                csr_pem = open(self.csr_file).read().replace("\r", "")
            except:
                logger.fatal("Unable to open CSR file: %s" % self.csr_file)
                sys.exit(1)

        if csr_return_format == 'der':
            return key_pem, csr_der

        return key_pem, csr_pem

            
    def filter_names(self, names):
        choices = [(n, "", 0) for n in names]
        result = self.d.checklist("Which names would you like to activate HTTPS for?", choices=choices)
        if result[0] != 0 or not result[1]:
            sys.exit(1)
        return result[1]

    def choice_of_ca(self):
        choices = self.get_cas()

        result = self.d.menu("Pick a Certificate Authority.  They're all unique and special!", width=70, choices=choices)

        if result[0] != 0:
            sys.exit(1)

        return result

    def get_cas(self):
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

                # random.shuffle(DV_choices)
                # random.shuffle(OV_choices)
                # random.shuffle(EV_choices)
                choices = DV_choices + OV_choices + EV_choices
            
        except IOError as e:
            logger.fatal("Unable to find .ca_offerings file")
            sys.exit(1)

        return choices

    def get_all_names(self):
	self.names = self.config.get_all_names()
        
        if not self.names:
            logger.fatal("No domain names were found in your apache config")
            logger.fatal("Either specify which names you would like trustify to validate or add server names to your virtual hosts")
            sys.exit(1)
        
        
    def init_logger(self):
        if self.curses:
            logger.setLogger(logger.NcursesLogger())
            logger.setLogLevel(logger.INFO)
        else:
            logger.setLogger(logger.FileLogger(sys.stdout))
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


def recognized_ca(issuer):
    pass

def gen_req_from_cert():
    return


def renew(config):
    cert_key_pairs = config.get_all_certs_keys()
    for tup in cert_key_pairs:
        cert = M2Crypto.X509.load_cert(tup[0])
        issuer = cert.get_issuer()
        if recognized_ca(issuer):
            generate_renewal_req()

        # Wait for response, act accordingly
    gen_req_from_cert()

    

# vim: set expandtab tabstop=4 shiftwidth=4
