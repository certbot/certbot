"""Revoker module to enable LE revocations."""
import collections
import csv
import logging
import os
import shutil

import M2Crypto

from letsencrypt.client import acme
from letsencrypt.client import CONFIG
from letsencrypt.client import errors
from letsencrypt.client import le_util
from letsencrypt.client import network

from letsencrypt.client.display import display_util
from letsencrypt.client.display import revocation


class Revoker(object):
    """A revocation class for LE.

    ..todo:: Add a method to specify your own certificate for revocation - CLI

    :ivar network: Network object
    :type network: :class:`letsencrypt.client.network`

    :ivar installer: Installer object
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    """

    list_path = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST")
    marked_path = os.path.join(CONFIG.CERT_KEY_BACKUP, "MARKED")

    def __init__(self, server, installer):
        self.network = network.Network(server)
        self.installer = installer
        # This will go through and make sure that nothing almost got revoked...
        # but didn't quite make it... also, guarantees no orphan cert/key files
        self.recovery_routine()

    def revoke_from_interface(self, cert):
        """Handle ACME "revocation" phase.

        :param cert: cert intended to be revoked
        :type cert: :class:`letsencrypt.client.revoker.Cert`

        """
        self._mark_for_revocation(cert)

        revoc = self.revoke(cert.backup_path, cert.backup_key_path)

        self.remove_cert_key(cert)
        self._remove_mark()

        if revoc is not None:
            revocation.success_revocation(cert)
        else:
            # TODO: Display a nice explanation
            pass

        self.display_menu()

    def revoke(self, cert_path, key_path):
        """Revoke the certificate with the ACME server.

        :param str cert_path: path to certificate file
        :param str key_path: path to associated private key or authorized key

        """
        try:
            cert_der = M2Crypto.X509.load_cert(cert_path).as_der()
            with open(key_path, "rU") as backup_key_file:
                key = backup_key_file.read()

        # If either of the files don't exist... or are corrupted
        except (OSError, IOError, M2Crypto.X509.X509Error):
            return None

        # TODO: Catch error associated with already revoked and proceed.
        return self.network.send_and_receive_expected(
            acme.revocation_request(cert_der, key), "revocation")

    def recovery_routine(self):
        """Intended to make sure files aren't orphaned."""
        if not os.path.isfile(Revoker.marked_path):
            return
        with open(Revoker.marked_path, "r") as marked_file:
            csvreader = csv.reader(marked_file)
            for row in csvreader:
                self.revoke(row[0], row[1])
                le_util.safely_remove(row[0])
                le_util.safely_remove(row[1])

        self._remove_mark()

    def _mark_for_revocation(self, cert):  # pylint: disable=no-self-use
        """Marks a cert for revocation."""
        if os.path.isfile(Revoker.marked_path):
            raise errors.LetsEncryptRevokerError(
                "MARKED file was never cleaned.")
        with open(Revoker.marked_path, "w") as marked_file:
            csvwriter = csv.writer(marked_file)
            csvwriter.writerow([cert.backup_path, cert.backup_key_path])

    def _remove_mark(self):  # pylint: disable=no-self-use
        """Remove the marked file."""
        os.remove(Revoker.marked_path)

    def display_menu(self):
        """List trusted Let's Encrypt certificates."""

        if not os.path.isfile(Revoker.list_path):
            logging.info(
                "You don't have any certificates saved from letsencrypt")
            return

        csha1_vhlist = self._get_installed_locations()
        certs = self._populate_saved_certs(csha1_vhlist)

        if certs:
            cert = revocation.choose_certs(certs)
            self.revoke_from_interface(cert)
        else:
            logging.info(
                "There are not any trusted Let's Encrypt "
                "certificates for this server.")

    def _populate_saved_certs(self, csha1_vhlist):
        # pylint: disable=no-self-use
        """Populate a list of all the saved certs."""
        certs = []
        with open(Revoker.list_path, "rb") as csvfile:
            csvreader = csv.reader(csvfile)
            # idx, orig_cert, orig_key
            for row in csvreader:
                # Generate backup key/cert names
                b_k = os.path.join(CONFIG.CERT_KEY_BACKUP,
                                   os.path.basename(row[2]) + "_" + row[0])
                b_c = os.path.join(CONFIG.CERT_KEY_BACKUP,
                                   os.path.basename(row[1]) + "_" + row[0])

                cert = Cert(b_c)
                # Set the meta data
                cert.add_meta(int(row[0]), row[1], row[2], b_c, b_k)
                # If we were able to find the cert installed... update status
                cert.installed = csha1_vhlist.get(cert.get_fingerprint(), [])

                certs.append(cert)

        return certs

    def _get_installed_locations(self):
        """Get installed locations of certificates

        :returns: cert sha1 fingerprint -> :class:`list` of vhosts where
            the certificate is installed.

        """
        csha1_vhlist = {}

        if self.installer is None:
            return csha1_vhlist

        for (cert_path, _, path) in self.installer.get_all_certs_keys():
            try:
                cert_sha1 = M2Crypto.X509.load_cert(
                    cert_path).get_fingerprint(md="sha1")
                if cert_sha1 in csha1_vhlist:
                    csha1_vhlist[cert_sha1].append(path)
                else:
                    csha1_vhlist[cert_sha1] = [path]
            except (IOError, M2Crypto.X509.X509Error):
                continue

        return csha1_vhlist

    def remove_cert_key(self, cert):  # pylint: disable=no-self-use
        """Remove certificate and key.

        :param cert: cert object
        :type cert: :class:`letsencrypt.client.revoker.Cert`

        """
        self._remove_cert_from_list(cert)

        # Remove files
        os.remove(cert.backup_path)
        os.remove(cert.backup_key_path)

    def _remove_cert_from_list(self, cert):  # pylint: disable=no-self-use
        """Remove a certificate from the LIST file."""
        list_path2 = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST.tmp")

        with open(Revoker.list_path, "rb") as orgfile:
            csvreader = csv.reader(orgfile)

            with open(list_path2, "wb") as newfile:
                csvwriter = csv.writer(newfile)

                for row in csvreader:
                    if not (row[0] == str(cert.idx) and
                            row[1] == cert.orig.path and
                            row[2] == cert.orig_key.path):
                        csvwriter.writerow(row)

        shutil.copy2(list_path2, Revoker.list_path)
        os.remove(list_path2)

    @classmethod
    def store_cert_key(cls, cert_path, key_path, encrypt=False):
        """Store certificate key. (Used to allow quick revocation)

        :param str cert_path: Path to a certificate file.
        :param key_path: Authorized key for certificate
        :type key_path: :class:`letsencrypt.client.le_util.Key`

        :param bool encrypt: Should the certificate key be encrypted?

        :returns: True if key file was stored successfully, False otherwise.
        :rtype: bool

        """
        le_util.make_or_verify_dir(CONFIG.CERT_KEY_BACKUP, 0o700)
        idx = 0

        if encrypt:
            logging.error(
                "Unfortunately securely storing the certificates/"
                "keys is not yet available. Stay tuned for the "
                "next update!")
            return False

        cls._append_index_file(cert_path, key_path)

        shutil.copy2(key_path,
                     os.path.join(
                         CONFIG.CERT_KEY_BACKUP,
                         os.path.basename(key_path) + "_" + str(idx)))
        shutil.copy2(cert_path,
                     os.path.join(
                         CONFIG.CERT_KEY_BACKUP,
                         os.path.basename(cert_path) + "_" + str(idx)))

        return True

    @classmethod
    def _append_index_file(cls, cert_path, key_path):
        if os.path.isfile(Revoker.list_path):
            with open(Revoker.list_path, 'r+b') as csvfile:
                csvreader = csv.reader(csvfile)

                # Find the highest index in the file
                for row in csvreader:
                    idx = int(row[0]) + 1
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow([str(idx), cert_path, key_path])

        else:
            with open(Revoker.list_path, 'wb') as csvfile:
                csvwriter = csv.writer(csvfile)
                csvwriter.writerow(["0", cert_path, key_path])


class Cert(object):
    """Cert object used for convenience.

    :ivar cert: M2Crypto X509 cert
    :type cert: :class:`M2Crypto.X509`

    :ivar int idx: convenience index used for listing
    :ivar orig: (`str` original certificate filepath, `str` status)
    :type orig: PathStatus
    :ivar orig_key: named tuple with(`str` original auth key path, `str` status)
    :type orig_key: :class:`PathStatus`
    :ivar str backup_path: backup filepath of the certificate
    :ivar str backup_key_path: backup filepath of the authorized key

    :ivar list installed: `list` of `str` describing all locations the cert
        is installed

    """
    PathStatus = collections.namedtuple("PathStatus", "path status")
    """Convenience container to hold path and status info"""

    def __init__(self, cert_path):
        """Cert initialization

        :param str cert_filepath: Name of file containing certificate in
            PEM format.

        """
        try:
            self.cert = M2Crypto.X509.load_cert(cert_path)
        except (IOError, M2Crypto.X509.X509Error):
            self.cert = None

        self.idx = -1

        self.orig = None
        self.orig_key = None
        self.backup_path = ""
        self.backup_key_path = ""

        self.installed = ["Unknown"]


    def add_meta(self, idx, orig, orig_key, backup, backup_key):
        """Add meta data to cert

        :param int idx: convenience index for revoker
        :param tuple orig: (`str` original certificate filepath, `str` status)
        :param tuple orig_key: (`str` original auth key path, `str` status)
        :param str backup: backup certificate filepath
        :param str backup_key: backup key filepath

        """
        deleted_msg = "This file has been moved or deleted"
        changed_msg = "This file has changed"
        status = ""
        key_status = ""

        # Verify original cert path
        if not os.path.isfile(orig):
            status = deleted_msg
        else:
            o_cert = M2Crypto.X509.load_cert(orig)
            if self.get_fingerprint() != o_cert.get_fingerprint(md="sha1"):
                status = changed_msg

        # Verify original key path
        if not os.path.isfile(orig_key):
            key_status = deleted_msg
        else:
            with open(orig_key, "r") as fd:
                key_pem = fd.read()
            with open(backup_key, "r") as fd:
                backup_key_pem = fd.read()
            if key_pem != backup_key_pem:
                key_status = changed_msg

        self.idx = idx
        self.orig = Cert.PathStatus(orig, status)
        self.orig_key = Cert.PathStatus(orig_key, key_status)
        self.backup_path = backup
        self.backup_key_path = backup_key

    def get_installed_msg(self):
        """Access installed message."""
        return ", ".join(self.installed)

    def get_subject(self):
        """Get subject."""
        return self.cert.get_subject().as_text()

    def get_cn(self):
        """Get common name."""
        return self.cert.get_subject().CN

    def get_issuer(self):
        """Get issuer."""
        return self.cert.get_issuer().as_text()

    def get_fingerprint(self):
        """Get sha1 fingerprint."""
        return self.cert.get_fingerprint(md="sha1")

    def get_not_before(self):
        """Get not_valid_before field."""
        return self.cert.get_not_before().get_datetime()

    def get_not_after(self):
        """Get not_valid_after field."""
        return self.cert.get_not_after().get_datetime()

    def get_serial(self):
        """Get serial number."""
        self.cert.get_serial_number()

    def get_pub_key(self):
        """Get public key size."""
        # .. todo:: M2Crypto doesn't support ECC, this will have to be updated
        return "RSA " + str(self.cert.get_pubkey().size() * 8)

    def get_san(self):
        """Get subject alternative name if available."""
        try:
            return self.cert.get_ext("subjectAltName").get_value()
        except LookupError:
            return ""

    def __str__(self):
        text = []
        text.append("Subject: %s" % self.get_subject())
        text.append("SAN: %s" % self.get_san())
        text.append("Issuer: %s" % self.get_issuer())
        text.append("Public Key: %s" % self.get_pub_key())
        text.append("Not Before: %s" % str(self.get_not_before()))
        text.append("Not After: %s" % str(self.get_not_after()))
        text.append("Serial Number: %s" % self.get_serial())
        text.append("SHA1: %s" % self.get_fingerprint())
        text.append("Installed: %s" % self.get_installed_msg())
        return os.linesep.join(text)

    def pretty_print(self):
        """Nicely frames a cert str"""
        text = "-" * (display_util.WIDTH - 4) + os.linesep
        text += str(self)
        text += "-" * (display_util.WIDTH - 4)
        return text
