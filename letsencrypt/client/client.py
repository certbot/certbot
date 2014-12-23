"""ACME protocol client class and helper functions."""
import collections
import csv
import logging
import os
import shutil
import socket
import string
import sys

import M2Crypto
import zope.component

from letsencrypt.client import acme
from letsencrypt.client import challenge
from letsencrypt.client import challenge_util
from letsencrypt.client import CONFIG
from letsencrypt.client import crypto_util
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util
from letsencrypt.client import network


# it's weird to point to chocolate servers via raw IPv6 addresses, and
# such addresses can be %SCARY in some contexts, so out of paranoia
# let's disable them by default
ALLOW_RAW_IPV6_SERVER = False


class Client(object):
    """ACME protocol client.

    :ivar network: Network object for sending and receiving messages
    :type network: :class:`letsencrypt.client.network.Network`

    :ivar list names: Domain names (:class:`list` of :class:`str`).

    :ivar authkey: Authorization Key
    :type authkey: :class:`letsencrypt.client.client.Client.Key`

    :ivar auth: Object that supports the IAuthenticator interface.
    :type auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

    :ivar installer: Object supporting the IInstaller interface.
    :type installer: :class:`letsencrypt.client.interfaces.IInstraller`

    """
    Key = collections.namedtuple("Key", "file pem")
    CSR = collections.namedtuple("CSR", "file data form")

    def __init__(self, server, names, authkey, auth, installer):
        """Initialize a client."""
        self.network = network.Network(server)
        self.names = names
        self.authkey = authkey

        sanity_check_names([server] + names)

        self.auth = auth
        self.installer = installer

    def obtain_certificate(self, csr,
                           cert_path=CONFIG.CERT_PATH,
                           chain_path=CONFIG.CHAIN_PATH):
        """Obtains a certificate from the ACME server.

        :param csr: A valid CSR in DER format for the certificate the client
            intends to receive.
        :type csr: :class:`CSR`

        :param str cert_path: Full desired path to end certificate.
        :param str chain_path: Full desired path to end chain file.

        :returns: cert_file, chain_file (paths to respective files)
        :rtype: `tuple` of `str`

        """
        # Request Challenges
        challenge_msg = self.acme_challenge()

        # Perform Challenges
        responses, auth_c, client_c = self.verify_identity(challenge_msg)

        # Get Authorization
        self.acme_authorization(challenge_msg, auth_c, client_c, responses)

        # Retrieve certificate
        certificate_dict = self.acme_certificate(csr.data)

        # Save Certificate
        cert_file, chain_file = self.save_certificate(
            certificate_dict, cert_path, chain_path)

        self.store_cert_key(cert_file, False)

        return cert_file, chain_file

    def acme_challenge(self):
        """Handle ACME "challenge" phase.

        .. todo:: Handle more than one domain name in self.names

        :returns: ACME "challenge" message.
        :rtype: dict

        """
        return self.network.send_and_receive_expected(
            acme.challenge_request(self.names[0]), "challenge")

    def acme_authorization(self, challenge_msg, auth_c, client_c, responses):
        """Handle ACME "authorization" phase.

        :param dict challenge_msg: ACME "challenge" message.

        :param chal_objs: TODO - this will be a new object...
        :param responses: TODO

        :returns: ACME "authorization" message.
        :rtype: dict

        """
        try:
            return self.network.send_and_receive_expected(
                acme.authorization_request(
                    challenge_msg["sessionID"], self.names[0],
                    challenge_msg["nonce"], responses, self.authkey.pem),
                "authorization")
        except errors.LetsEncryptClientError as err:
            logging.fatal(str(err))
            logging.fatal(
                "Failed Authorization procedure - cleaning up challenges")
            sys.exit(1)
        finally:
            self.cleanup_challenges(auth_c, client_c)

    def acme_certificate(self, csr_der):
        """Handle ACME "certificate" phase.

        :param str csr_der: CSR in DER format.

        :returns: ACME "certificate" message.
        :rtype: dict

        """
        logging.info("Preparing and sending CSR...")
        return self.network.send_and_receive_expected(
            acme.certificate_request(csr_der, self.authkey.pem), "certificate")

    # pylint: disable=no-self-use
    def save_certificate(self, certificate_dict, cert_path, chain_path):
        """Saves the certificate received from the ACME server.

        :param dict certificate_dict: certificate message from server
        :param str cert_path: Path to attempt to save the cert file
        :param str chain_path: Path to attempt to save the chain file

        :returns: cert_file, chain_file (absolute paths to the actual files)
        :rtype: `tuple` of `str`

        :raises IOError: If unable to find room to write the cert files

        """
        cert_chain_abspath = None
        cert_fd, cert_file = le_util.unique_file(cert_path, 0o644)
        cert_fd.write(
            crypto_util.b64_cert_to_pem(certificate_dict["certificate"]))
        cert_fd.close()
        logging.info(
            "Server issued certificate; certificate written to %s", cert_file)

        if certificate_dict.get("chain", None):
            chain_fd, chain_fn = le_util.unique_file(chain_path, 0o644)
            for cert in certificate_dict.get("chain", []):
                chain_fd.write(crypto_util.b64_cert_to_pem(cert))
            chain_fd.close()

            logging.info("Cert chain written to %s", chain_fn)

            # This expects a valid chain file
            cert_chain_abspath = os.path.abspath(chain_fn)

        return os.path.abspath(cert_file), cert_chain_abspath

    def deploy_certificate(self, privkey, cert_file, chain_file):
        """Install certificate

        :returns: Path to a certificate file.
        :rtype: str

        """
        # Find set of virtual hosts to deploy certificates to
        vhost = self.get_virtual_hosts(self.names)

        chain = None if chain_file is None else os.path.abspath(chain_file)

        for host in vhost:
            self.installer.deploy_cert(host,
                                       os.path.abspath(cert_file),
                                       os.path.abspath(privkey.file),
                                       chain)
            # Enable any vhost that was issued to, but not enabled
            if not host.enabled:
                logging.info("Enabling Site %s", host.filep)
                self.installer.enable_site(host)

        self.installer.save("Deployed Let's Encrypt Certificate")
        # sites may have been enabled / final cleanup
        self.installer.restart()

        zope.component.getUtility(
            interfaces.IDisplay).success_installation(self.names)

        return vhost

    def optimize_config(self, vhost, redirect=None):
        """Optimize the configuration.

        .. todo:: Handle multiple vhosts

        :param vhost: vhost to optimize
        :type vhost: :class:`letsencrypt.client.apache.obj.VirtualHost`

        :param redirect: If traffic should be forwarded from HTTP to HTTPS.
        :type redirect: bool or None

        """
        if redirect is None:
            redirect = zope.component.getUtility(
                interfaces.IDisplay).redirect_by_default()

        if redirect:
            self.redirect_to_ssl(vhost)
            self.installer.restart()

        # if self.ocsp_stapling is None:
        #     q = ("Would you like to protect the privacy of your users "
        #         "by enabling OCSP stapling? If so, your users will not have "
        #         "to query the Let's Encrypt CA separately about the current "
        #         "revocation status of your certificate.")
        #    self.ocsp_stapling = self.ocsp_stapling = display.ocsp_stapling(q)
        # if self.ocsp_stapling:
        #    # TODO enable OCSP Stapling
        #    continue

    def cleanup_challenges(self, auth_c, client_c):
        """Cleanup configuration challenges

        :param dict challenges: challenges from a challenge message

        """
        logging.info("Cleaning up challenges...")
        self.auth.cleanup(auth_c)
        # should cleanup client_c
        assert not client_c

    def verify_identity(self, challenge_msg):
        """Verify identity.

        :param dict challenge_msg: ACME "challenge" message.

        :returns: TODO
        :rtype: dict

        """
        path = challenge.gen_challenge_path(
            challenge_msg["challenges"], challenge_msg.get("combinations", []))

        logging.info("Performing the following challenges:")

        # Every indices element is a list of integers referring to which
        # challenges in the master list the challenge object satisfies
        # Single Challenge objects that can satisfy multiple server challenges
        # mess up the order of the challenges, thus requiring the indices
        auth_c, auth_i, client_c, client_i = self.challenge_factory(
            self.names[0], challenge_msg["challenges"], path)

        responses = ["null"] * len(challenge_msg["challenges"])

        # Do client centric challenges here...
        # Since this isn't implemented yet...
        assert not client_i
        auth_resp = self.auth.perform(auth_c)
        self._assign_responses(auth_resp, auth_i, responses)

        logging.info(
            "Configured Apache for challenges; waiting for verification...")

        return responses, auth_c, client_c

    # pylint: disable=no-self-use
    def _assign_responses(self, resp, index_list, responses):
        """Assign chall_response to appropriate places in response list.

        :param resp: responses from a challenge
        :type resp: list of dicts

        :param list index_list: respective challenges resp satisfies
        :param list responses: master list of responses

        """
        assert len(resp) == len(index_list)
        for j, index in enumerate(index_list):
            responses[index] = resp[j]


    def store_cert_key(self, cert_file, encrypt=False):
        """Store certificate key.

        :param str cert_file: Path to a certificate file.

        :param bool encrypt: Should the certificate key be encrypted?

        :returns: True if key file was stored successfully, False otherwise.
        :rtype: bool

        """
        list_file = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST")
        le_util.make_or_verify_dir(CONFIG.CERT_KEY_BACKUP, 0o700)
        idx = 0

        if encrypt:
            logging.error(
                "Unfortunately securely storing the certificates/"
                "keys is not yet available. Stay tuned for the "
                "next update!")
            return False

        if os.path.isfile(list_file):
            with open(list_file, 'r+b') as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:
                    idx = int(row[0]) + 1
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow([str(idx), cert_file, self.authkey.file])

        else:
            with open(list_file, 'wb') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(["0", cert_file, self.authkey.file])

        shutil.copy2(self.authkey.file,
                     os.path.join(
                         CONFIG.CERT_KEY_BACKUP,
                         os.path.basename(self.authkey.file) + "_" + str(idx)))
        shutil.copy2(cert_file,
                     os.path.join(
                         CONFIG.CERT_KEY_BACKUP,
                         os.path.basename(cert_file) + "_" + str(idx)))

        return True

    def redirect_to_ssl(self, vhost):
        """Redirect all traffic from HTTP to HTTPS

        :param vhost: list of ssl_vhosts
        :type vhost: :class:`letsencrypt.client.interfaces.IInstaller`

        """
        for ssl_vh in vhost:
            success, redirect_vhost = self.installer.enable_redirect(ssl_vh)
            logging.info(
                "\nRedirect vhost: %s - %s ", redirect_vhost.filep, success)
            # If successful, make sure redirect site is enabled
            if success:
                self.installer.enable_site(redirect_vhost)

    def get_virtual_hosts(self, domains):
        """Retrieve the appropriate virtual host for the domain

        :param list domains: Domains to find ssl vhosts for

        :returns: associated vhosts
        :rtype: :class:`letsencrypt.client.apache.obj.VirtualHost`

        """
        vhost = set()
        for name in domains:
            host = self.installer.choose_virtual_host(name)
            if host is not None:
                vhost.add(host)
        return vhost

    def challenge_factory(self, domain, challenges, path):
        """

        :param str domain: domain of the enrollee

        :param list challenges: A list of challenges from ACME "challenge"
            server message to be fulfilled by the client in order to prove
            possession of the identifier.

        :param list path: List of indices from `challenges`.

        :returns: A pair of TODO
        :rtype: tuple

        """
        auth_chall = []
        # Since a single invocation of SNI challenge can satisfy multiple
        # challenges. We must keep track of all the challenges it satisfies
        auth_satisfies = []

        client_chall = []
        client_satisfies = []
        for index in path:
            chall = challenges[index]

            if chall["type"] == "dvsni":
                logging.info("  DVSNI challenge for name %s.", domain)
                auth_satisfies.append(index)
                auth_chall.append(challenge_util.DVSNI_Chall(
                    str(domain), str(chall["r"]),
                    str(chall["nonce"]), self.authkey))

            elif chall["type"] == "recoveryToken":
                logging.info("  Recovery Token Challenge for name: %s.", domain)
                client_satisfies.append(index)
                client_chall.append({
                    type: "recoveryToken",
                })

            else:
                logging.fatal("Challenge not currently supported")
                sys.exit(82)

        return auth_chall, auth_satisfies, client_chall, client_satisfies


def validate_key_csr(privkey, csr):
    """Validate CSR and key files.

    Verifies that the client key and csr arguments are valid and correspond to
    one another. This does not currently check the names in the CSR.

    :param privkey: Key associated with CSR
    :type privkey: :class:`letsencrypt.client.client.Client.Key`

    :param csr: CSR
    :type csr: :class:`letsencrypt.client.client.Client.CSR`

    :raises LetsEncryptClientError: if validation fails

    """
    # TODO: Handle all of these problems appropriately
    # The client can eventually do things like prompt the user
    # and allow the user to take more appropriate actions

    if csr.form == "der":
        csr_obj = M2Crypto.X509.load_request_der_string(csr.data)
        csr = Client.CSR(csr.file, csr_obj.as_pem(), "der")

    # If CSR is provided, it must be readable and valid.
    if csr.data and not crypto_util.valid_csr(csr.data):
        raise errors.LetsEncryptClientError(
            "The provided CSR is not a valid CSR")

    # If key is provided, it must be readable and valid.
    if privkey.pem and not crypto_util.valid_privkey(privkey.pem):
        raise errors.LetsEncryptClientError(
            "The provided key is not a valid key")

    # If CSR and key are provided, the key must be the same key used
    # in the CSR.
    if csr.data and privkey.pem:
        if not crypto_util.csr_matches_pubkey(
                csr.data, privkey.pem):
            raise errors.LetsEncryptClientError(
                "The key and CSR do not match")


def init_key():
    """Initializes privkey.

    Inits key and CSR using provided files or generating new files
    if necessary. Both will be saved in PEM format on the
    filesystem. The CSR is placed into DER format to allow
    the namedtuple to easily work with the protocol.

    """
    key_pem = crypto_util.make_key(CONFIG.RSA_KEY_SIZE)

    # Save file
    le_util.make_or_verify_dir(CONFIG.KEY_DIR, 0o700)
    key_f, key_filename = le_util.unique_file(
        os.path.join(CONFIG.KEY_DIR, "key-letsencrypt.pem"), 0o600)
    key_f.write(key_pem)
    key_f.close()

    logging.info("Generating key: %s", key_filename)

    return Client.Key(key_filename, key_pem)


def init_csr(privkey, names):
    """Initialize a CSR with the given private key."""

    csr_pem, csr_der = crypto_util.make_csr(privkey.pem, names)

    # Save CSR
    le_util.make_or_verify_dir(CONFIG.CERT_DIR, 0o755)
    csr_f, csr_filename = le_util.unique_file(
        os.path.join(CONFIG.CERT_DIR, "csr-letsencrypt.pem"), 0o644)
    csr_f.write(csr_pem)
    csr_f.close()

    logging.info("Creating CSR: %s", csr_filename)

    return Client.CSR(csr_filename, csr_der, "der")


def csr_pem_to_der(csr):
    """Convert pem CSR to der."""

    csr_obj = M2Crypto.X509.load_request_string(csr.data)
    return Client.CSR(csr.file, csr_obj.as_der(), "der")


def sanity_check_names(names):
    """Make sure host names are valid.

    :param list names: List of host names

    """
    for name in names:
        if not is_hostname_sane(name):
            logging.fatal("%r is an impossible hostname", name)
            sys.exit(81)


def is_hostname_sane(hostname):
    """Make sure the given host name is sane.

    Do enough to avoid shellcode from the environment.  There's
    no need to do more.

    :param str hostname: Host name to validate

    :returns: True if hostname is valid, otherwise false.
    :rtype: bool

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
    except socket.error:
        return False
