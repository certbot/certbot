import csv
import json
import os
import shutil
import socket
import string
import sys
import time

import jsonschema
import M2Crypto
import requests

from letsencrypt.client import acme
from letsencrypt.client import apache_configurator
from letsencrypt.client import challenge
from letsencrypt.client import CONFIG
from letsencrypt.client import crypto_util
from letsencrypt.client import display
from letsencrypt.client import le_util
from letsencrypt.client import logger


# it's weird to point to chocolate servers via raw IPv6 addresses, and
# such addresses can be %SCARY in some contexts, so out of paranoia
# let's disable them by default
ALLOW_RAW_IPV6_SERVER = False


class Client(object):
    """ACME protocol client."""

    def __init__(self, ca_server, cert_signing_request=None,
                 private_key=None, use_curses=True):
        self.curses = use_curses

        # Logger needs to be initialized before Configurator
        self.init_logger()
        # TODO: Can probably figure out which configurator to use
        #       without special packaging based on system info Command
        #       line arg or client function to discover
        self.config = apache_configurator.ApacheConfigurator(
            CONFIG.SERVER_ROOT)

        self.server = ca_server

        self.csr_file = cert_signing_request
        self.key_file = private_key

        # If CSR is provided, the private key should also be provided.
        if self.csr_file and not self.key_file:
            logger.fatal("Please provide the private key file used in \
            generating the provided CSR")
            sys.exit(1)
        # If CSR is provided, it must be readable and valid.
        try:
            if self.csr_file and not crypto.util.valid_csr(self.csr_file):
                logger.fatal("The provided CSR is not a valid CSR")
                sys.exit(1)
        except IOError, e:
            logger.fatal("The provided CSR could not be read")
            sys.exit(1)
        # If key is provided, it must be readable and valid.
        try:
            if self.key_file and not crypto.util.valid_privkey(self.key_file):
                logger.fatal("The provided key is not a valid key")
                sys.exit(1)
        except IOError, e:
            logger.fatal("The provided key could not be read")
            sys.exit(1)
        # If CSR and key are provided, the key must be the same key used
        # in the CSR.
        if self.csr_file and self.key_file and not csr_matches_pubkey(self.csr_file, self.key_file):
            logger.fatal("The provided key is not the same key referred to by \
            the CSR file")
            sys.exit(1)

        self.server_url = "https://%s/acme/" % self.server

    def authenticate(self, domains=None, redirect=None, eula=False):
        domains = [] if domains is None else domains

        # Check configuration
        if not self.config.config_test():
            sys.exit(1)

        self.redirect = redirect

        # Display preview warning
        if not eula:
            with open('EULA') as eula_file:
                if not display.generic_yesno(eula_file.read(),
                                             "Agree", "Cancel"):
                    sys.exit(0)

        # Display screen to select domains to validate
        if domains:
            sanity_check_names([self.server] + domains)
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

        # Request Challenges
        challenge_msg = self.acme_challenge()

        # Get key and csr to perform challenges
        _, csr_der = self.get_key_csr_pem()

        # Perform Challenges
        responses, challenge_objs = self.verify_identity(challenge_msg)
        # Get Authorization
        self.acme_authorization(challenge_msg, challenge_objs, responses)

        # Retrieve certificate
        certificate_dict = self.acme_certificate(csr_der)

        # Find set of virtual hosts to deploy certificates to
        vhost = self.get_virtual_hosts(self.names)

        # Install Certificate
        cert_file = self.install_certificate(certificate_dict, vhost)

        # Perform optimal config changes
        self.optimize_config(vhost)

        self.config.save("Completed Let's Encrypt Authentication")

        self.store_cert_key(cert_file, False)

    def acme_challenge(self):
        """Handle ACME "challenge" phase.

        :returns: ACME "challenge" message.
        :rtype: dict

        """
        return self.send_and_receive_expected(
            acme.challenge_request(self.names), "challenge")

    def acme_authorization(self, challenge_msg, chal_objs, responses):
        """Handle ACME "authorization" phase.

        :param challenge_msg: ACME "challenge" message.
        :type challenge_msg: dict

        :param chal_objs: TODO
        :type chal_objs: TODO

        :param responses: TODO
        :type responses: TODO

        :returns: ACME "authorization" message.
        :rtype: dict

        """
        auth_dict = self.send(acme.authorization_request(
            challenge_msg["sessionID"], self.names[0],
            challenge_msg["nonce"], responses, self.key_file))

        try:
            return self.is_expected_msg(auth_dict, "authorization")
        except:
            logger.fatal("Failed Authorization procedure - "
                         "cleaning up challenges")
            sys.exit(1)
        finally:
            self.cleanup_challenges(chal_objs)

    def acme_certificate(self, csr_der):
        """Handle ACME "certificate" phase.

        :param csr_der: TODO
        :type csr_der: TODO

        :returns: ACME "certificate" message.
        :rtype: dict

        """
        logger.info("Preparing and sending CSR..")
        return self.send_and_receive_expected(
            acme.certificate_request(csr_der, self.key_file), "certificate")

    def acme_revocation(self, cert):
        """Handle ACME "revocation" phase.

        :param cert: TODO
        :type cert: dict

        :returns: ACME "revocation" message.
        :rtype: dict

        """
        cert_der = M2Crypto.X509.load_cert(cert["backup_cert_file"]).as_der()

        revocation = self.send_and_receive_expected(
            acme.revocation_request(cert["backup_key_file"], cert_der),
            "revocation")

        display.generic_notification(
            "You have successfully revoked the certificate for "
            "%s" % cert["cn"], width=70, height=9)

        remove_cert_key(cert)
        self.list_certs_keys()

        return revocation

    def send(self, msg):
        """Send ACME message to server.

        :param msg: ACME message (JSON serializable).
        :type msg: dict

        :raises: TypeError if `msg` is not JSON serializable or
                 jsonschema.ValidationError if not valid ACME message or
                 Exception if response from server is not valid ACME message

        :returns: Server response message.
        :rtype: dict

        """
        json_encoded = json.dumps(msg)
        acme.acme_object_validate(json_encoded)

        try:
            response = requests.post(
                self.server_url,
                data=json_encoded,
                headers={"Content-Type": "application/json"},
            )
        except requests.exceptions.RequestException as error:
            logger.fatal("Send() failed... may have lost connection to server")
            logger.fatal(" ** ERROR **")
            logger.fatal(error)
            sys.exit(8)

        try:
            acme.acme_object_validate(response.content)
        except jsonschema.ValidationError:
            raise Exception('Response from server is not a valid ACME message')

        return response.json()

    def send_and_receive_expected(self, msg, expected):
        """Send ACME message to server and return expected message.

        :param msg: ACME message (JSON serializable).
        :type acem_msg: dict

        :param expected: Name of the expected response ACME message type.
        :type expected: str

        :returns: ACME response message of expected type.
        :rtype: dict

        """
        response = self.send(msg)
        try:
            return self.is_expected_msg(response, expected)
        except:  # TODO: too generic exception
            raise Exception('Expected message (%s) not received' % expected)

    def is_expected_msg(self, response, expected, delay=3, rounds=20):
        """Is reponse expected ACME message?

        :param response: ACME response message from server.
        :type response: dict

        :param expected: Name of the expected response ACME message type.
        :type expected: str

        :param delay: Number of seconds to delay before next round in case
                      of ACME "defer" response message.
        :type delay: int

        :param rounds: Number of resend attempts in case of ACME "defer"
                       reponse message.
        :type rounds: int

        :raises: Exception

        :returns: ACME response message from server.
        :rtype: dict

        """
        for _ in xrange(rounds):
            if response["type"] == expected:
                return response

            elif response["type"] == "error":
                logger.error("%s: %s - More Info: %s" %
                             (response["error"],
                              response.get("message", ""),
                              response.get("moreInfo", "")))
                raise Exception(response["error"])

            elif response["type"] == "defer":
                logger.info("Waiting for %d seconds..." % delay)
                time.sleep(delay)
                response = self.send(acme.status_request(response["token"]))
            else:
                logger.fatal("Received unexpected message")
                logger.fatal("Expected: %s" % expected)
                logger.fatal("Received: " + response)
                sys.exit(33)

        logger.error("Server has deferred past the max of %d seconds" %
                     (rounds * delay))

    def list_certs_keys(self):
        list_file = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST")
        certs = []

        if not os.path.isfile(list_file):
            logger.info(
                "You don't have any certificates saved from letsencrypt")
            return

        c_sha1_vh = {}
        for (cert, _, path) in self.config.get_all_certs_keys():
            try:
                c_sha1_vh[M2Crypto.X509.load_cert(
                    cert).get_fingerprint(md='sha1')] = path
            except:
                continue

        with open(list_file, 'rb') as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                cert = crypto_util.get_cert_info(row[1])

                b_k = os.path.join(CONFIG.CERT_KEY_BACKUP,
                                   os.path.basename(row[2]) + "_" + row[0])
                b_c = os.path.join(CONFIG.CERT_KEY_BACKUP,
                                   os.path.basename(row[1]) + "_" + row[0])

                cert.update({
                    "orig_key_file": row[2],
                    "orig_cert_file": row[1],
                    "idx": int(row[0]),
                    "backup_key_file": b_k,
                    "backup_cert_file": b_c,
                    "installed": c_sha1_vh.get(cert["fingerprint"], ""),
                })
                certs.append(cert)
        if certs:
            self.choose_certs(certs)
        else:
            display.generic_notification(
                "There are not any trusted Let's Encrypt "
                "certificates for this server.")

    def choose_certs(self, certs):
        """Display choose certificates menu.

        :param certs: List of cert dicts.
        :type certs: list

        """
        code, tag = display.display_certs(certs)
        cert = certs[tag]

        if code == display.OK:
            if display.confirm_revocation(cert):
                self.acme_revocation(cert)
            else:
                self.choose_certs(certs)
        elif code == display.HELP:
            print code, tag, cert
            display.more_info_cert(cert)
            self.choose_certs(certs)
        else:
            exit(0)

    def install_certificate(self, certificate_dict, vhost):
        """Install certificate

        :returns: Path to a certificate file.
        :rtype: str

        """
        cert_chain_abspath = None
        cert_fd, cert_file = le_util.unique_file(CONFIG.CERT_PATH, 644)
        cert_fd.write(
            crypto_util.b64_cert_to_pem(certificate_dict["certificate"]))
        cert_fd.close()
        logger.info("Server issued certificate; certificate written to %s" %
                    cert_file)

        if certificate_dict.get("chain", None):
            chain_fd, chain_fn = le_util.unique_file(CONFIG.CHAIN_PATH, 644)
            for cert in certificate_dict.get("chain", []):
                chain_fd.write(crypto_util.b64_cert_to_pem(cert))
            chain_fd.close()

            logger.info("Cert chain written to %s" % chain_fn)

            # This expects a valid chain file
            cert_chain_abspath = os.path.abspath(chain_fn)

        for host in vhost:
            self.config.deploy_cert(host,
                                    os.path.abspath(cert_file),
                                    os.path.abspath(self.key_file),
                                    cert_chain_abspath)
            # Enable any vhost that was issued to, but not enabled
            if not host.enabled:
                logger.info("Enabling Site " + host.file)
                self.config.enable_site(host)

        # sites may have been enabled / final cleanup
        self.config.restart(quiet=self.curses)

        display.success_installation(self.names)

        return cert_file

    def optimize_config(self, vhost):
        if self.redirect is None:
            self.redirect = display.redirect_by_default()

        if self.redirect:
            self.redirect_to_ssl(vhost)
            self.config.restart(quiet=self.curses)

        # if self.ocsp_stapling is None:
        #     q = ("Would you like to protect the privacy of your users "
        #         "by enabling OCSP stapling? If so, your users will not have "
        #         "to query the Let's Encrypt CA separately about the current "
        #         "revocation status of your certificate.")
        #    self.ocsp_stapling = self.ocsp_stapling = display.ocsp_stapling(q)
        # if self.ocsp_stapling:
        #    # TODO enable OCSP Stapling
        #    continue

    def cleanup_challenges(self, challenges):
        logger.info("Cleaning up challenges...")
        for chall in challenges:
            if chall["type"] in CONFIG.CONFIG_CHALLENGES:
                self.config.cleanup()
            else:
                # Handle other cleanup if needed
                pass

    def verify_identity(self, challenge_msg):
        """Verify identity.

        :param challenge_msg: ACME "challenge" message.
        :type challenge_msg: dict

        :returns: TODO
        :rtype: dict

        """
        path = challenge.gen_challenge_path(
            challenge_msg["challenges"], challenge_msg.get("combinations", []))

        logger.info("Performing the following challenges:")

        # Every indices element is a list of integers referring to which
        # challenges in the master list the challenge object satisfies
        # Single Challenge objects that can satisfy multiple server challenges
        # mess up the order of the challenges, thus requiring the indices
        challenge_objs, indices = self.challenge_factory(
            self.names[0], challenge_msg["challenges"], path)

        responses = ["null"] * len(challenge_msg["challenges"])

        # Perform challenges
        for i, c_obj in enumerate(challenge_objs):
            response = "null"
            if c_obj["type"] in CONFIG.CONFIG_CHALLENGES:
                response = self.config.perform(c_obj)
            else:
                # Handle RecoveryToken type challenges
                pass

            for index in indices[i]:
                responses[index] = response

        logger.info("Configured Apache for challenges; " +
                    "waiting for verification...")

        return responses, challenge_objs

    def store_cert_key(self, cert_file, encrypt=False):
        """Store certificate key.

        :param cert_file: Path to a certificate file.
        :type cert_file: str

        :param encrypt: Should the certificate key be encrypted?
        :type encrypt: bool

        """
        list_file = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST")
        le_util.make_or_verify_dir(CONFIG.CERT_KEY_BACKUP, 0700)
        idx = 0

        if encrypt:
            logger.error("Unfortunately securely storing the certificates/"
                         "keys is not yet available. Stay tuned for the "
                         "next update!")
            return False

        if os.path.isfile(list_file):
            with open(list_file, 'r+b') as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:
                    idx = int(row[0]) + 1
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow([str(idx), cert_file, self.key_file])

        else:
            with open(list_file, 'wb') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(["0", cert_file, self.key_file])

        shutil.copy2(self.key_file,
                     os.path.join(
                         CONFIG.CERT_KEY_BACKUP,
                         os.path.basename(self.key_file) + "_" + str(idx)))
        shutil.copy2(cert_file,
                     os.path.join(
                         CONFIG.CERT_KEY_BACKUP,
                         os.path.basename(cert_file) + "_" + str(idx)))

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
        """

        :param name: TODO
        :type name: TODO

        :param challanges: A list of challenges from ACME "challenge"
                           server message to be fulfilled by the client
                           in order to prove possession of the identifier.
        :type challenges: list

        :param path: List of indices from `challenges`.
        :type path: list

        :returns: A pair of TODO
        :rtype: tuple

        """
        sni_todo = []
        # Since a single invocation of SNI challenge can satisfy multiple
        # challenges. We must keep track of all the challenges it satisfies
        sni_satisfies = []

        challenge_objs = []
        challenge_obj_indices = []
        for index in path:
            chall = challenges[index]

            if chall["type"] == "dvsni":
                logger.info("  DVSNI challenge for name %s." % name)
                sni_satisfies.append(index)
                sni_todo.append((str(name), str(chall["r"]),
                                 str(chall["nonce"])))

            elif chall["type"] == "recoveryToken":
                logger.info("\tRecovery Token Challenge for name: %s." % name)
                challenge_obj_indices.append(index)
                challenge_objs.append({
                    type: "recoveryToken",
                })

            else:
                logger.fatal("Challenge not currently supported")
                sys.exit(82)

        if sni_todo:
            # SNI_Challenge can satisfy many sni challenges at once so only
            # one "challenge object" is issued for all sni_challenges
            challenge_objs.append({
                "type": "dvsni",
                "listSNITuple": sni_todo,
                "dvsni_key": os.path.abspath(self.key_file),
            })
            challenge_obj_indices.append(sni_satisfies)
            logger.debug(sni_todo)

        return challenge_objs, challenge_obj_indices

    def get_key_csr_pem(self, csr_return_format='der'):
        """
        Returns key and CSR using provided files or generating new files if
        necessary. Both will be saved in pem format on the filesystem.
        The CSR can optionally be returned in DER format as the CSR cannot be
        loaded back into M2Crypto.
        """
        key_pem = None
        csr_pem = None
        if not self.key_file:
            key_pem = crypto_util.make_key(CONFIG.RSA_KEY_SIZE)
            # Save file
            le_util.make_or_verify_dir(CONFIG.KEY_DIR, 0700)
            key_f, self.key_file = le_util.unique_file(
                os.path.join(CONFIG.KEY_DIR, "key-letsencrypt.pem"), 0600)
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
            le_util.make_or_verify_dir(CONFIG.CERT_DIR, 0755)
            csr_f, self.csr_file = le_util.unique_file(
                os.path.join(CONFIG.CERT_DIR, "csr-letsencrypt.pem"), 0644)
            csr_f.write(csr_pem)
            csr_f.close()
            logger.info("Creating CSR: %s" % self.csr_file)
        else:
            # TODO fix this der situation
            try:
                csr_pem = open(self.csr_file).read().replace("\r", "")
            except:
                logger.fatal("Unable to open CSR file: %s" % self.csr_file)
                sys.exit(1)

        if csr_return_format == 'der':
            return key_pem, csr_der

        return key_pem, csr_pem

    # def choice_of_ca(self):
    #     choices = self.get_cas()
    #     message = ("Pick a Certificate Authority. "
    #                "They're all unique and special!")
    #     in_txt = ("Enter the number of a Certificate Authority "
    #               "(c to cancel): ")
    #     code, selection = display.generic_menu(message, choices, in_txt)

    #     if code != display.OK:
    #         sys.exit(0)

    #     return selection

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
        """Return all valid names in the configuration."""
        names = list(self.config.get_all_names())
        sanity_check_names(names)

        if not names:
            logger.fatal("No domain names were found in your apache config")
            logger.fatal("Either specify which names you would like "
                         "letsencrypt to validate or add server names "
                         "to your virtual hosts")
            sys.exit(1)

        return names

    def init_logger(self):
        if self.curses:
            logger.setLogger(logger.NcursesLogger())
            logger.setLogLevel(logger.INFO)
        else:
            logger.setLogger(logger.FileLogger(sys.stdout))
            logger.setLogLevel(logger.INFO)


def remove_cert_key(cert):
    """Remove certificate key.

    :param cert:
    :type cert: dict

    """
    list_file = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST")
    list_file2 = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST.tmp")

    with open(list_file, 'rb') as orgfile:
        csvreader = csv.reader(orgfile)

        with open(list_file2, 'wb') as newfile:
            csvwriter = csv.writer(newfile)

            for row in csvreader:
                if not (row[0] == str(cert["idx"]) and
                        row[1] == cert["orig_cert_file"] and
                        row[2] == cert["orig_key_file"]):
                    csvwriter.writerow(row)

    shutil.copy2(list_file2, list_file)
    os.remove(list_file2)
    os.remove(cert["backup_cert_file"])
    os.remove(cert["backup_key_file"])


def sanity_check_names(names):
    for name in names:
        if not is_hostname_sane(name):
            logger.fatal(repr(name) + " is an impossible hostname")
            sys.exit(81)


def is_hostname_sane(hostname):
    """
    Do enough to avoid shellcode from the environment.  There's
    no need to do more.
    """
    # hostnames & IPv4
    allowed = string.ascii_letters + string.digits + "-."
    if all([c in allowed for c in hostname]):
        return True

    if not ALLOW_RAW_IPV6_SERVER:
        return False

    # ipv6 is messy and complicated, can contain %zoneindex etc.
    try:
        # is this a valid IPv6 address?
        socket.getaddrinfo(hostname, 443, socket.AF_INET6)
        return True
    except:
        return False
