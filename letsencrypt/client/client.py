"""ACME protocol client class and helper functions."""
import collections
import csv
import logging
import os
import shutil
import sys

import M2Crypto
import zope.component

from letsencrypt.client import acme
from letsencrypt.client import auth_handler
from letsencrypt.client import client_authenticator
from letsencrypt.client import CONFIG
from letsencrypt.client import crypto_util
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util
from letsencrypt.client import network
from letsencrypt.client import reverter
from letsencrypt.client import revoker

from letsencrypt.client.apache import configurator
from letsencrypt.client.le_util import Key


class Client(object):
    """ACME protocol client.

    :ivar network: Network object for sending and receiving messages
    :type network: :class:`letsencrypt.client.network.Network`

    :ivar authkey: Authorization Key
    :type authkey: :class:`letsencrypt.client.client.Client.Key`

    :ivar auth_handler: Object that supports the IAuthenticator interface.
        auth_handler contains both a dv_authenticator and a client_authenticator
    :type auth_handler: :class:`letsencrypt.client.auth_handler.AuthHandler`

    :ivar installer: Object supporting the IInstaller interface.
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    """
    zope.interface.implements(interfaces.IAuthenticator)

    # Note: form is the type of data, "pem" or "der"
    CSR = collections.namedtuple("CSR", "file data form")

    def __init__(self, server, authkey, dv_auth, installer):
        """Initialize a client.

        :param str server: CA server to contact
        :param dv_auth: IAuthenticator Interface that can solve the
            CONFIG.DV_CHALLENGES
        :type dv_auth: :class:`letsencrypt.client.interfaces.IAuthenticator`

        """
        self.network = network.Network(server)
        self.authkey = authkey

        self.installer = installer

        if dv_auth is not None:
            client_auth = client_authenticator.ClientAuthenticator(server)
            self.auth_handler = auth_handler.AuthHandler(
                dv_auth, client_auth, self.network)
        else:
            self.auth_handler = None

    def obtain_certificate(self, domains, csr=None,
                           cert_path=CONFIG.CERT_PATH,
                           chain_path=CONFIG.CHAIN_PATH):
        """Obtains a certificate from the ACME server.

        :param str domains: list of domains to get a certificate
        :param csr: CSR must contain requested domains, the key used to generate
            this CSR can be different than self.authkey
        :type csr: :class:`CSR`

        :param str cert_path: Full desired path to end certificate.
        :param str chain_path: Full desired path to end chain file.

        :returns: cert_file, chain_file (paths to respective files)
        :rtype: `tuple` of `str`

        """
        if self.auth_handler is None:
            logging.warning("Unable to obtain a certificate, because client "
                            "does not have a valid auth handler.")

        # Request Challenges
        for name in domains:
            self.auth_handler.add_chall_msg(
                name, self.acme_challenge(name), self.authkey)

        # Perform Challenges/Get Authorizations
        self.auth_handler.get_authorizations()

        # Create CSR from names
        if csr is None:
            csr = init_csr(self.authkey, domains)

        # Retrieve certificate
        certificate_dict = self.acme_certificate(csr.data)

        # Save Certificate
        cert_file, chain_file = self.save_certificate(
            certificate_dict, cert_path, chain_path)

        self.store_cert_key(cert_file, False)

        return cert_file, chain_file

    def acme_challenge(self, domain):
        """Handle ACME "challenge" phase.

        :returns: ACME "challenge" message.
        :rtype: dict

        """
        return self.network.send_and_receive_expected(
            acme.challenge_request(domain), "challenge")

    def acme_certificate(self, csr_der):
        """Handle ACME "certificate" phase.

        :param str csr_der: CSR in DER format.

        :returns: ACME "certificate" message.
        :rtype: dict

        """
        logging.info("Preparing and sending CSR...")
        return self.network.send_and_receive_expected(
            acme.certificate_request(csr_der, self.authkey.pem), "certificate")

    def save_certificate(self, certificate_dict, cert_path, chain_path):
        # pylint: disable=no-self-use
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

    def deploy_certificate(self, domains, privkey, cert_file, chain_file=None):
        """Install certificate

        :param list domains: list of domains to install the certificate

        :param privkey: private key for certificate
        :type privkey: :class:`Key`

        :param str cert_file: certificate file path
        :param str chain_file: chain file path

        """
        if self.installer is None:
            logging.warning("No installer specified, client is unable to deploy"
                            "the certificate")
            raise errors.LetsEncryptClientError("No installer available")

        chain = None if chain_file is None else os.path.abspath(chain_file)

        for dom in domains:
            self.installer.deploy_cert(dom,
                                       os.path.abspath(cert_file),
                                       os.path.abspath(privkey.file),
                                       chain)

        self.installer.save("Deployed Let's Encrypt Certificate")
        # sites may have been enabled / final cleanup
        self.installer.restart()

        zope.component.getUtility(
            interfaces.IDisplay).success_installation(domains)

    def enhance_config(self, domains, redirect=None):
        """Enhance the configuration.

        .. todo:: This needs to handle the specific enhancements offered by the
            installer. We will also have to find a method to pass in the chosen
            values efficiently.

        :param list domains: list of domains to configure

        :param redirect: If traffic should be forwarded from HTTP to HTTPS.
        :type redirect: bool or None

        :raises :class:`letsencrypt.client.errors.LetsEncryptClientError`: if
            no installer is specified in the client.

        """
        if self.installer is None:
            logging.warning("No installer is specified, there isn't any "
                            "configuration to enhance.")
            raise errors.LetsEncryptClientError("No installer available")

        if redirect is None:
            redirect = zope.component.getUtility(
                interfaces.IDisplay).redirect_by_default()

        if redirect:
            self.redirect_to_ssl(domains)

    def store_cert_key(self, cert_file, encrypt=False):
        """Store certificate key. (Used to allow quick revocation)

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

    def redirect_to_ssl(self, domains):
        """Redirect all traffic from HTTP to HTTPS

        :param vhost: list of ssl_vhosts
        :type vhost: :class:`letsencrypt.client.interfaces.IInstaller`

        """
        for dom in domains:
            try:
                self.installer.enhance(dom, "redirect")
            except errors.LetsEncryptConfiguratorError:
                logging.warn('Unable to perform redirect for %s', dom)

        self.installer.save("Add Redirects")
        self.installer.restart()


def validate_key_csr(privkey, csr=None):
    """Validate Key and CSR files.

    Verifies that the client key and csr arguments are valid and correspond to
    one another. This does not currently check the names in the CSR due to
    the inability to read SANs from CSRs in python crypto libraries.

    If csr is left as None, only the key will be validated.

    :param privkey: Key associated with CSR
    :type privkey: :class:`letsencrypt.client.client.Client.Key`

    :param csr: CSR
    :type csr: :class:`letsencrypt.client.client.Client.CSR`

    :raises LetsEncryptClientError: if validation fails

    """
    # TODO: Handle all of these problems appropriately
    # The client can eventually do things like prompt the user
    # and allow the user to take more appropriate actions

    # Key must be readable and valid.
    if privkey.pem and not crypto_util.valid_privkey(privkey.pem):
        raise errors.LetsEncryptClientError(
            "The provided key is not a valid key")

    if csr:
        if csr.form == "der":
            csr_obj = M2Crypto.X509.load_request_der_string(csr.data)
            csr = Client.CSR(csr.file, csr_obj.as_pem(), "der")

        # If CSR is provided, it must be readable and valid.
        if csr.data and not crypto_util.valid_csr(csr.data):
            raise errors.LetsEncryptClientError(
                "The provided CSR is not a valid CSR")

        # If both CSR and key are provided, the key must be the same key used
        # in the CSR.
        if csr.data and privkey.pem:
            if not crypto_util.csr_matches_pubkey(
                    csr.data, privkey.pem):
                raise errors.LetsEncryptClientError(
                    "The key and CSR do not match")


def init_key(key_size):
    """Initializes privkey.

    Inits key and CSR using provided files or generating new files
    if necessary. Both will be saved in PEM format on the
    filesystem. The CSR is placed into DER format to allow
    the namedtuple to easily work with the protocol.

    """
    try:
        key_pem = crypto_util.make_key(key_size)
    except ValueError as err:
        logging.fatal(str(err))
        logging.info("Note: The default RSA key size is %d bits.",
                     CONFIG.RSA_KEY_SIZE)
        sys.exit(1)

    # Save file
    le_util.make_or_verify_dir(CONFIG.KEY_DIR, 0o700)
    key_f, key_filename = le_util.unique_file(
        os.path.join(CONFIG.KEY_DIR, "key-letsencrypt.pem"), 0o600)
    key_f.write(key_pem)
    key_f.close()

    logging.info("Generating key (%d bits): %s", key_size, key_filename)

    return Key(key_filename, key_pem)


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


# This should be controlled by commandline parameters
def determine_authenticator():
    """Returns a valid IAuthenticator."""
    try:
        return configurator.ApacheConfigurator()
    except errors.LetsEncryptNoInstallationError:
        logging.info("Unable to determine a way to authenticate the server")


def determine_installer():
    """Returns a valid installer if one exists."""
    try:
        return configurator.ApacheConfigurator()
    except errors.LetsEncryptNoInstallationError:
        logging.info("Unable to find a way to install the certificate.")


def rollback(checkpoints):
    """Revert configuration the specified number of checkpoints.

    .. note:: If another installer uses something other than the reverter class
        to do their configuration changes, the correct reverter will have to be
        determined.

    .. note:: This function restarts the server even if there weren't any
        rollbacks.  The user may be confused or made an error and simply needs
        to restart the server.

    .. todo:: This function will have to change depending on the functionality
        of future installers.  Perhaps the interface should define errors that
        are thrown for the various functions.

    :param int checkpoints: Number of checkpoints to revert.

    """
    # Misconfigurations are only a slight problems... allow the user to rollback
    try:
        installer = determine_installer()
    except errors.LetsEncryptMisconfigurationError:
        _misconfigured_rollback(checkpoints)
        return

    # No Errors occurred during init... proceed normally
    # If installer is None... couldn't find an installer... there shouldn't be
    # anything to rollback
    if installer is not None:
        installer.rollback_checkpoints(checkpoints)
        installer.restart()


def _misconfigured_rollback(checkpoints):
    """Handles the case where the Installer is misconfigured."""
    yes = zope.component.getUtility(interfaces.IDisplay).generic_yesno(
        "Oh, no! The web server is currently misconfigured.{0}{0}"
        "Would you still like to rollback the "
        "configuration?".format(os.linesep))
    if not yes:
        logging.info("The error message is above.")
        logging.info("Configuration was not rolled back.")
        return

    logging.info("Rolling back using the Reverter module")
    # recovery routine has probably already been run by installer
    # in the__init__ attempt, run it again for safety... it shouldn't hurt
    # Also... not sure how future installers will handle recovery.
    rev = reverter.Reverter()
    rev.recovery_routine()
    rev.rollback_checkpoints(checkpoints)

    # We should try to restart the server
    try:
        installer = determine_installer()
        installer.restart()
        logging.info("Hooray!  Rollback solved the misconfiguration!")
        logging.info("Your web server is back up and running.")
    except errors.LetsEncryptMisconfigurationError:
        logging.warning(
            "Rollback was unable to solve the misconfiguration issues")


def revoke(server):
    """Revoke certificates.

    :param str server: ACME server the client wishes to revoke certificates from

    """
    # Misconfigurations don't really matter. Determine installer better choose
    # correctly though.
    try:
        installer = determine_installer()
    except errors.LetsEncryptMisconfigurationError:
        zope.component.getUtility(interfaces.IDisplay).generic_notification(
            "The web server is currently misconfigured. Some "
            "abilities like seeing which certificates are currently "
            "installed may not be available.")
        installer = None

    # This is a temporary fix to avoid errors. The Revoker is not fully
    # developed.
    if installer is None:
        zope.component.getUtility(interfaces.IDisplay).generic_notification(
            "The Let's Encrypt Revoker module does not currently support "
            "revocation without a valid installer.  This feature should come "
            "soon.")
        return
    revoc = revoker.Revoker(server, installer)
    revoc.list_certs_keys()


def view_config_changes():
    """View checkpoints and associated configuration changes.

    .. note:: This assumes that the installation is using a Reverter object.

    """
    rev = reverter.Reverter()
    rev.recovery_routine()
    rev.view_config_changes()
