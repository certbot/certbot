#!/usr/bin/env python

import M2Crypto
import json
import os, time, sys, shutil

import csv

import requests

from letsencrypt.client.acme import acme_object_validate
from letsencrypt.client.sni_challenge import SNI_Challenge
from letsencrypt.client import configurator, apache_configurator
from letsencrypt.client import logger, display
from letsencrypt.client import le_util, crypto_util
from letsencrypt.client.CONFIG import RSA_KEY_SIZE, CERT_PATH
from letsencrypt.client.CONFIG import CHAIN_PATH, SERVER_ROOT, KEY_DIR, CERT_DIR
from letsencrypt.client.CONFIG import CERT_KEY_BACKUP, EXCLUSIVE_CHALLENGES
from letsencrypt.client.CONFIG import CHALLENGE_PREFERENCES, CONFIG_CHALLENGES
# it's weird to point to chocolate servers via raw IPv6 addresses, and such
# addresses can be %SCARY in some contexts, so out of paranoia let's disable
# them by default
allow_raw_ipv6_server = False

class Client(object):
    # In case of import, dialog needs scope over the class
    dialog = None

    def __init__(self, ca_server, cert_signing_request=None,
                 private_key=None, use_curses=True):
        global dialog
        self.curses = use_curses

        # Logger needs to be initialized before Configurator
        self.init_logger()
        # TODO:  Can probably figure out which configurator to use without
        #        special packaging based on system info
        #        Command line arg or client function to discover
        self.config = apache_configurator.ApacheConfigurator(SERVER_ROOT)

        self.server = ca_server

        self.csr_file = cert_signing_request
        self.key_file = private_key

        # If CSR is provided, the private key should also be provided.
        # TODO: Make sure key was actually used in CSR
        # TODO: Make sure key has proper permissions
        if self.csr_file and not self.key_file:
            logger.fatal("Please provide the private key file used in \
            generating the provided CSR")
            sys.exit(1)

        self.server_url = "https://%s/acme/" % self.server

    def authenticate(self, domains = [], redirect = None, eula = False):
        # Check configuration
        if not self.config.configtest():
            sys.exit(1)

        self.redirect = redirect

        # Display preview warning
        if not eula:
            with open('EULA') as f:
                if not display.generic_yesno(f.read(), "Agree", "Disagree"):
                    sys.exit(0)

        # Display screen to select domains to validate
        if domains:
            self.sanity_check_names([self.server] + domains)
            self.names = domains
        else:
            # This function adds all names
            # found within the config to self.names
            # Then filters them based on user selection
            code, self.names = display.filter_names(self.get_all_names())
            if code == display.OK and self.names:
                # TODO: Allow multiple names once it is setup
                self.names = [self.names[0]]
            else:
                sys.exit(0)

        # Display choice of CA screen
        # TODO: Use correct server depending on CA
        #choice = self.choice_of_ca()

        #Request Challenges
        challenge_dict = self.handle_challenge()

        # Get key and csr to perform challenges
        key_pem, csr_der = self.get_key_csr_pem()

        #Perform Challenges
        responses, challenge_objs = self.verify_identity(challenge_dict)
        # Get Authorization
        self.handle_authorization(challenge_dict, challenge_objs, responses)

        # Retrieve certificate
        certificate_dict = self.handle_certificate(csr_der)


        # Find set of virtual hosts to deploy certificates to
        vhost = self.get_virtual_hosts(self.names)

        # Install Certificate
        self.install_certificate(certificate_dict, vhost)

        # Perform optimal config changes
        self.optimize_config(vhost)

        self.config.save("Completed Let's Encrypt Authentication")

        self.store_cert_key(False)

        return


    def handle_challenge(self):
        challenge_dict = self.send(self.challenge_request(self.names))
        try:
            return self.is_expected_msg(challenge_dict, "challenge")
        except:
            logger.fatal("Unexpected error")
            sys.exit(1)

    def handle_authorization(self, challenge_dict, chal_objs, responses):
        auth_dict = self.send(self.authorization_request(
            challenge_dict["sessionID"], self.names[0],
            challenge_dict["nonce"], responses))

        try:
            return self.is_expected_msg(auth_dict, "authorization")
        except:
            logger.fatal("Failed Authorization procedure - \
            cleaning up challenges")
            sys.exit(1)

        finally:
            self.cleanup_challenges(chal_objs)


    def handle_certificate(self, csr_der):
        certificate_dict = self.send(
            self.certificate_request(csr_der, self.key_file))

        try:
            return self.is_expected_msg(certificate_dict, "certificate")
        except:
            logger.fatal("Encountered unexpected message")
            sys.exit(1)


    def revoke(self, c):
        x = M2Crypto.X509.load_cert(c["backup_cert_file"])
        cert_der = x.as_der()

        #self.find_key_for_cert()
        revocation_dict = self.send(
            self.revocation_request(c["backup_key_file"], cert_der))

        revocation_dict = self.is_expected_msg(revocation_dict, "revocation")

        display.generic_notification(
            "You have successfully revoked the certificate for %s" % c["cn"], width=70, height=9)

        self.remove_cert_key(c)

        self.list_certs_keys()

    def remove_cert_key(self, c):
        list_file = CERT_KEY_BACKUP + "LIST"
        list_file2 = CERT_KEY_BACKUP + "LIST.tmp"
        with open(list_file, 'rb') as orgfile:
            csvreader = csv.reader(orgfile)
            with open(list_file2, 'wb') as newfile:
                csvwriter = csv.writer(newfile)
                for row in csvreader:
                    if not (row[0] == str(c["idx"]) and
                            row[1] == c["orig_cert_file"] and
                            row[2] == c["orig_key_file"]):
                        csvwriter.writerow(row)

        shutil.copy2(list_file2, list_file)
        os.remove(list_file2)
        os.remove(c['backup_cert_file'])
        os.remove(c['backup_key_file'])


    def list_certs_keys(self):
        list_file = CERT_KEY_BACKUP + "LIST"
        certs = []

        if not os.path.isfile(CERT_KEY_BACKUP + "LIST"):
            logger.info("You don't have any certificates saved from letsencrypt")
            return

        c_sha1_vh = {}
        for x in self.config.get_all_certs_keys():
            try:
                c_sha1_vh[M2Crypto.X509.load_cert(x[0]).get_fingerprint(md='sha1')] = x[2]
            except:
                continue

        with open(list_file, 'rb') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                c = crypto_util.get_cert_info(row[1])

                b_k = CERT_KEY_BACKUP + os.path.basename(row[2]) + "_" + row[0]
                b_c = CERT_KEY_BACKUP + os.path.basename(row[1]) + "_" + row[0]

                c["orig_key_file"] = row[2]
                c["orig_cert_file"] = row[1]
                c["idx"] = int(row[0])
                c["backup_key_file"] = b_k
                c["backup_cert_file"] = b_c
                c["installed"] = c_sha1_vh.get(c["fingerprint"], "")

                certs.append(c)
        if certs:
            self.choose_certs(certs)
        else:
            display.generic_notification("There are not any trusted \
            Let's Encrypt certificates for this server.")

    def choose_certs(self, certs):
        code, s = display.display_certs(certs)
        if code == display.OK:
            if display.confirm_revocation(certs[s]):
                self.revoke(certs[s])
            else:
                self.choose_certs(certs)
        elif code == display.HELP:
            print code, s, certs[s]
            display.more_info_cert(certs[s])
            self.choose_certs(certs)
        else:
            exit(0)


    def revocation_request(self, key_file, cert_der):
        return {"type":"revocationRequest",
                "certificate":le_util.b64_url_enc(cert_der),
                "signature":crypto_util.create_sig(cert_der, key_file)}


    def install_certificate(self, certificate_dict, vhost):
        cert_chain_abspath = None
        cert_fd, self.cert_file = le_util.unique_file(CERT_PATH, 644)
        cert_fd.write(
            crypto_util.b64_cert_to_pem(certificate_dict["certificate"]))
        cert_fd.close()
        logger.info("Server issued certificate; certificate written to %s" %
                    self.cert_file)

        if certificate_dict.get("chain", None):
            chain_fd, chain_fn = le_util.unique_file(CHAIN_PATH, 644)
            for c in certificate_dict.get("chain", []):
                chain_fd.write(crypto_util.b64_cert_to_pem(c))
            chain_fd.close()

            logger.info("Cert chain written to %s" % chain_fn)

            # This expects a valid chain file
            cert_chain_abspath = os.path.abspath(chain_fn)

        for host in vhost:
            self.config.deploy_cert(host,
                                    os.path.abspath(self.cert_file),
                                    os.path.abspath(self.key_file),
                                    cert_chain_abspath)
            # Enable any vhost that was issued to, but not enabled
            if not host.enabled:
                logger.info("Enabling Site " + host.file)
                self.config.enable_site(host)

        # sites may have been enabled / final cleanup
        self.config.restart(quiet=self.curses)

        display.success_installation(self.names)


    def optimize_config(self, vhost):
        if self.redirect is None:
            self.redirect = display.redirect_by_default()

        if self.redirect:
            self.redirect_to_ssl(vhost)
            self.config.restart(quiet=self.curses)

        #if self.ocsp_stapling is None:
            # q = "Would you like to protect the privacy of your users " +
            # "by enabling OCSP stapling? If so, your users will not have to " +
            # "query the Let's Encrypt CA separately about the current " +
            # "revocation status of your certificate."
            #self.ocsp_stapling = self.ocsp_stapling = display.ocsp_stapling(q)
        #if self.ocsp_stapling:
            # TODO enable OCSP Stapling
         #   continue


    def certificate_request(self, csr_der, key):
        logger.info("Preparing and sending CSR..")
        return {"type":"certificateRequest",
                "csr":le_util.b64_url_enc(csr_der),
                "signature":crypto_util.create_sig(csr_der, self.key_file)}

    def cleanup_challenges(self, challenge_objs):
        logger.info("Cleaning up challenges...")
        for c in challenge_objs:
            if c["type"] in CONFIG_CHALLENGES:
                self.config.cleanup()
            else:
                #Handle other cleanup if needed
                pass

    def is_expected_msg(self, msg_dict, expected, delay=3, rounds = 20):
        for i in range(rounds):
            if msg_dict["type"] == expected:
                return msg_dict

            elif msg_dict["type"] == "error":
                logger.error("%s: %s - More Info: %s" %
                             (msg_dict["error"],
                              msg_dict.get("message", ""),
                              msg_dict.get("moreInfo", "")))
                raise Exception(msg_dict["error"])

            elif msg_dict["type"] == "defer":
                logger.info("Waiting for %d seconds..." % delay)
                time.sleep(delay)
                msg_dict = self.send(self.status_request(msg_dict["token"]))
            else:
                logger.fatal("Received unexpected message")
                logger.fatal("Expected: %s" % expected)
                logger.fatal("Received: " + msg_dict)
                sys.exit(33)

        logger.error("Server has deferred past the max of %d seconds" %
                     (rounds * delay))
        return None


    def authorization_request(self, id, name, server_nonce, responses):
        auth_req = {"type":"authorizationRequest",
                    "sessionID":id,
                    "nonce":server_nonce}

        auth_req["signature"] = crypto_util.create_sig(
            name + le_util.b64_url_dec(server_nonce), self.key_file)

        auth_req["responses"] = responses
        return auth_req

    def status_request(self, token):
        return {"type":"statusRequest", "token":token}

    def challenge_request(self, names):
        #logger.info("Temporarily only enabling one name")
        return {"type":"challengeRequest", "identifier": names[0]}

    def verify_identity(self, c):
        path = self.gen_challenge_path(
            c["challenges"], c.get("combinations", None))

        logger.info("Performing the following challenges:")

        # Every indicies element is a list of integers referring to which
        # challenges in the master list the challenge object satisfies
        # Single Challenge objects that can satisfy multiple server challenges
        # mess up the order of the challenges, thus requiring the indicies
        challenge_objs, indicies = self.challenge_factory(
            self.names[0], c["challenges"], path)

        responses = ["null"] * len(c["challenges"])

        # Perform challenges
        for i, c_obj in challenge_objs:
            response = "null"
            if c_obj["type"] in CONFIG_CHALLENGES:
                response = self.config.perform(c_obj)
            else:
                # Handle RecoveryToken type challenges
                pass

            for index in indicies[i]:
                responses[index] = response
        
        logger.info("Configured Apache for challenges; " +
        "waiting for verification...")

        return responses, challenge_objs

    def gen_challenge_path(self, challenges, combos):
        """
        Generate a plan to get authority over the identity
        TODO: Make sure that the challenges are feasible...
              Example: Do you have the recovery key?
        """

        if combos:
            return self.__find_smart_path(challenges, combos)

        return self.__find_dumb_path(challenges)

    def __find_smart_path(self, challenges, combos):
        """
        Can be called if combinations  is included
        Function uses a simple ranking system to choose the combo with the
        lowest cost
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
            logger.fatal("Client does not support any combination of \
            challenges to satisfy ACME server")
            sys.exit(22)

        return best_combo

    def __find_dumb_path(self, challenges):
        """
        Should be called if the combinations hint is not included by the server
        This function returns the best path that does not contain multiple
        mutually exclusive challenges
        """
        # Add logic for a crappy server
        # Choose a DV
        path = []
        for pref_c in CHALLENGE_PREFERENCES:
            for i, offered_c in enumerate(challenges):
                if (pref_c == offered_c["type"] and
                    self.is_preferred(offered_c["type"], path)):
                    path.append((i, offered_c["type"]))

        return [tup[0] for tup in path]


    def is_preferred(self, offered_c_type, path):
        for tup in path:
            for s in EXCLUSIVE_CHALLENGES:
                # Second part is in case we eventually allow multiple names
                # to be challenges at the same time
                if (tup[1] in s and offered_c_type in s and
                tup[1] != offered_c_type):
                    return False

        return True

    def send(self, json_obj):
        try:
            json_encoded = json.dumps(json_obj)
            acme_object_validate(json_encoded)
            response = requests.post(
                self.server_url,
                data=json_encoded,
                headers={"Content-Type": "application/json"},
            )
            body = response.content
            acme_object_validate(body)
            return response.json()
        except:
            logger.fatal("Send() failed... may have lost connection to server")
            sys.exit(8)


    def store_revocation_token(self, token):
        return



    def store_cert_key(self, encrypt = False):
        list_file = CERT_KEY_BACKUP + "LIST"
        le_util.make_or_verify_dir(CERT_KEY_BACKUP, 0700)
        idx = 0

        if encrypt:
            logger.error("Unfortunately securely storing the certificates/keys \
            is not yet available. Stay tuned for the next update!")
            return False

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

        shutil.copy2(self.key_file,
                     CERT_KEY_BACKUP + os.path.basename(self.key_file) +
                     "_" + str(idx))
        shutil.copy2(self.cert_file,
                     CERT_KEY_BACKUP + os.path.basename(self.cert_file) +
                     "_" + str(idx))


    def redirect_to_ssl(self, vhost):
        for ssl_vh in vhost:
         success, redirect_vhost = self.config.enable_redirect(ssl_vh)
         logger.info("\nRedirect vhost: " + redirect_vhost.file +
                     " - " + str(success))
         # If successful, make sure redirect site is enabled
         if success:
             self.config.enable_site(redirect_vhost)


    def get_virtual_hosts(self, domains):
        vhost = set()
        for name in domains:
            host = self.config.choose_virtual_host(name)
            if host is not None:
                vhost.add(host)
        return vhost

    def challenge_factory(self, name, challenges, path):
        sni_todo = []
        # Since a single invocation of SNI challenge can satisfy multiple
        # challenges. We must keep track of all the challenges it satisfies
        sni_satisfies = []

        challenge_objs = []
        challenge_obj_indicies = []
        for c in path:
            if challenges[c]["type"] == "dvsni":
                logger.info("  DVSNI challenge for name %s." % name)
                sni_satisfies.append(c)
                sni_todo.append( (str(name), str(challenges[c]["r"]),
                                  str(challenges[c]["nonce"])) )

            elif challenges[c]["type"] == "recoveryToken":
                logger.info("\tRecovery Token Challenge for name: %s." % name)
                challenge_objs_indicies.append(c)
                challenge_objs.append({type:"recoveryToken"})

            else:
                logger.fatal("Challenge not currently supported")
                sys.exit(82)

        if sni_todo:
            # SNI_Challenge can satisfy many sni challenges at once so only
            # one "challenge object" is issued for all sni_challenges
            challenge_objs.append({"type":"dvsni", "listSNITuple":snitodo
                                   "dvsni_key":os.path.abspath(self.key_file)})
            challenge_obj_indicies.append(sni_satisfies)
            logger.debug(sni_todo)

        return challenge_objs, challenge_obj_indicies


    def get_key_csr_pem(self, csr_return_format = 'der'):
        """
        Returns key and CSR using provided files or generating new files if
        necessary. Both will be saved in pem format on the filesystem.
        The CSR can optionally be returned in DER format as the CSR cannot be
        loaded back into M2Crypto.
        """
        key_pem = None
        csr_pem = None
        if not self.key_file:
            key_pem = crypto_util.make_key(RSA_KEY_SIZE)
            # Save file
            le_util.make_or_verify_dir(KEY_DIR, 0700)
            key_f, self.key_file = le_util.unique_file(
                KEY_DIR + "key-letsencrypt.pem", 0600)
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
            le_util.make_or_verify_dir(CERT_DIR, 0755)
            csr_f, self.csr_file = le_util.unique_file(
                CERT_DIR + "csr-letsencrypt.pem", 0644)
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


    def choice_of_ca(self):
        choices = self.get_cas()
        message = "Pick a Certificate Authority.  They're all unique and special!"
        in_txt = "Enter the number of a Certificate Authority (c to cancel): "
        code, selection = display.generic_menu(message, choices, in_txt)

        if code != display.OK:
            sys.exit(0)

        return selection

    # Legacy Code: Although I would like to see a free and open marketplace
    # in the future. The Let's Encrypt Client will not have this feature at
    # launch
    # def get_cas(self):
    #     DV_choices = []
    #     OV_choices = []
    #     EV_choices = []
    #     choices = []
    #     try:
    #         with open("/etc/letsencrypt/.ca_offerings") as f:
    #             for line in f:
    #                 choice = line.split(";", 1)
    #                 if 'DV' in choice[0]:
    #                     DV_choices.append(choice)
    #                 elif 'OV' in choice[0]:
    #                     OV_choices.append(choice)
    #                 else:
    #                     EV_choices.append(choice)

    #             # random.shuffle(DV_choices)
    #             # random.shuffle(OV_choices)
    #             # random.shuffle(EV_choices)
    #             choices = DV_choices + OV_choices + EV_choices
    #             choices = [(l[0], l[1]) for l in choices]

    #     except IOError as e:
    #         logger.fatal("Unable to find .ca_offerings file")
    #         sys.exit(1)

    #     return choices

    def get_all_names(self):
        """
        Should return all valid names in the configuration
        """
        names = list(self.config.get_all_names())
        self.sanity_check_names(names)

        if not names:
            logger.fatal("No domain names were found in your apache config")
            logger.fatal("Either specify which names you would like letsencrypt \
            to validate or add server names to your virtual hosts")
            sys.exit(1)

        return names

    def init_logger(self):
        if self.curses:
            logger.setLogger(logger.NcursesLogger())
            logger.setLogLevel(logger.INFO)
        else:
            logger.setLogger(logger.FileLogger(sys.stdout))
            logger.setLogLevel(logger.INFO)

    def sanity_check_names(self, names):
        for name in names:
            if not self.is_hostname_sane(name):
                logger.fatal(repr(name) + " is an impossible hostname")
                sys.exit(81)

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
