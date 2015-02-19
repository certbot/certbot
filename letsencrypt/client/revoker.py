"""Revoker module to enable LE revocations.

The backend of this module would fit a database quite nicely, but in order to
minimize dependencies and maintain transparency, the class currently implements
its own storage system.  The number of certs that will likely be stored on any
given client might not warrant requiring a database.

"""
import collections
import csv
import logging
import os
import shutil

import Crypto.PublicKey.RSA
import M2Crypto

from letsencrypt.acme import messages
from letsencrypt.acme import util as acme_util

from letsencrypt.client import errors
from letsencrypt.client import le_util
from letsencrypt.client import network

from letsencrypt.client.display import util as display_util
from letsencrypt.client.display import revocation


class Revoker(object):
    """A revocation class for LE.

    .. todo:: Add a method to specify your own certificate for revocation - CLI

    :ivar network: Network object
    :type network: :class:`letsencrypt.client.network`

    :ivar installer: Installer object
    :type installer: :class:`~letsencrypt.client.interfaces.IInstaller`

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.client.interfaces.IConfig`

    """
    def __init__(self, installer, config, no_confirm=False):
        self.network = network.Network(config.server)
        self.installer = installer
        self.config = config
        self.no_confirm = no_confirm

        le_util.make_or_verify_dir(config.cert_key_backup, 0o700, os.geteuid())

        # TODO: Find a better solution for this...
        self.list_path = os.path.join(config.cert_key_backup, "LIST")
        # Make sure that the file is available for use for rest of class
        open(self.list_path, "a").close()

    def revoke_from_key(self, authkey):
        """Revoke all certificates under an authorized key.

        :param authkey: Authorized key used in previous transactions
        :type authkey: :class:`letsencrypt.client.le_util.Key`

        """
        certs = []
        with open(self.list_path, "rb") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                # idx, cert, key
                # Add all keys that match to marked list
                # TODO: This doesn't account for padding in the file that might
                #   differ. This should only consider the key material.
                # Note: The key can be different than the pub key found in the
                #    certificate.
                _, b_k = self._row_to_backup(row)
                if authkey.pem == open(b_k).read():
                    certs.append(Cert.fromrow(row, self.config.cert_key_backup))

        if certs:
            self._safe_revoke(certs)

    def revoke_from_cert(self, cert_path):
        """Revoke a certificate by specifying a file path.

        :param str cert_path: path to ACME certificate in pem form

        """
        # Locate the correct certificate (do not rely on filename)
        cert_to_revoke = Cert(cert_path)

        with open(self.list_path, "rb") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                cert = Cert.fromrow(row, self.config.cert_key_backup)

                if cert == cert_to_revoke:
                    self._safe_revoke([cert])

    def revoke_from_menu(self):
        """List trusted Let's Encrypt certificates."""

        csha1_vhlist = self._get_installed_locations()
        certs = self._populate_saved_certs(csha1_vhlist)

        while True:
            if certs:
                selection = revocation.choose_certs(certs)

                revoked_certs = self._safe_revoke([certs[selection]])
                # Since we are currently only revoking one cert at a time...
                if revoked_certs:
                    # This is safer than using remove as Revoker.Certs only
                    # check the DER value of the cert. There could potentially
                    # be multiple backup certs with the same value.
                    del certs[selection]
            else:
                logging.info(
                    "There are not any trusted Let's Encrypt "
                    "certificates for this server.")
                return

    def _populate_saved_certs(self, csha1_vhlist):
        # pylint: disable=no-self-use
        """Populate a list of all the saved certs.

        It is important to read from the file rather than the directory.
        We assume that the LIST file is the master record and depending on
        program crashes, this may differ from what is actually in the directory.
        Namely, additional certs/keys may exist.  There should never be any
        certs/keys in the LIST that don't exist in the directory however.

        """
        certs = []
        with open(self.list_path, "rb") as csvfile:
            csvreader = csv.reader(csvfile)
            # idx, orig_cert, orig_key
            for row in csvreader:
                cert = Cert.fromrow(row, self.config.cert_key_backup)

                # If we were able to find the cert installed... update status
                cert.installed = csha1_vhlist.get(cert.get_fingerprint(), [])

                certs.append(cert)

        return certs

    def _get_installed_locations(self):
        """Get installed locations of certificates

        :returns: map from cert sha1 fingerprint to :class:`list` of vhosts
            where the certificate is installed.

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

    def _safe_revoke(self, certs):
        """Confirm and revoke certificates.

        :param certs: certs intended to be revoked
        :type certs: :class:`list` of :class:`letsencrypt.client.revoker.Cert`

        :returns: certs successfully revoked
        :rtype: :class:`list` of :class:`letsencrypt.client.revoker.Cert`

        """
        success_list = []
        try:
            for cert in certs:
                if self.no_confirm or revocation.confirm_revocation(cert):
                    try:
                        self._acme_revoke(cert)

                        success_list.append(cert)
                        revocation.success_revocation(cert)
                    except errors.LetsEncryptClientError:
                        # TODO: Improve error handling when networking is set...
                        logging.error(
                            "Unable to revoke cert:%s%s", os.linesep, str(cert))
        finally:
            if success_list:
                self._remove_certs_keys(success_list)

        return success_list

    def _acme_revoke(self, cert):
        """Revoke the certificate with the ACME server.

        :param cert: certificate to revoke
        :type cert: :class:`letsencrypt.client.revoker.Cert`

        :returns: TODO

        """
        try:
            certificate = acme_util.ComparableX509(cert.cert)
            with open(cert.backup_key_path, "rU") as backup_key_file:
                key = Crypto.PublicKey.RSA.importKey(backup_key_file.read())

        # If the key file doesn't exist... or is corrupted
        except (OSError, IOError):
            raise errors.LetsEncryptRevokerError("Unable to read key file")

        # TODO: Catch error associated with already revoked and proceed.
        return self.network.send_and_receive_expected(
            messages.RevocationRequest.create(
                certificate=certificate, key=key),
            messages.Revocation)

    def _remove_certs_keys(self, cert_list):  # pylint: disable=no-self-use
        """Remove certificate and key.

        :param list cert_list: Must contain certs, each is of type
            :class:`letsencrypt.client.revoker.Cert`

        """
        # This must occur first, LIST is the official key
        self._remove_certs_from_list(cert_list)

        # Remove files
        for cert in cert_list:
            os.remove(cert.backup_path)
            os.remove(cert.backup_key_path)

    def _remove_certs_from_list(self, cert_list):  # pylint: disable=no-self-use
        """Remove a certificate from the LIST file.

        :param list cert_list: Must contain valid certs, each is of type
            :class:`letsencrypt.client.revoker.Cert`

        """
        list_path2 = os.path.join(self.config.cert_key_backup, "LIST.tmp")

        idx = 0

        with open(self.list_path, "rb") as orgfile:
            csvreader = csv.reader(orgfile)
            with open(list_path2, "wb") as newfile:
                csvwriter = csv.writer(newfile)

                for row in csvreader:
                    if idx >= len(cert_list) or row != cert_list[idx].get_row():
                        csvwriter.writerow(row)
                    else:
                        idx += 1

        # This should never happen...
        if idx != len(cert_list):
            raise errors.LetsEncryptRevokerError(
                "Did not find all cert_list items to remove from LIST")

        shutil.copy2(list_path2, self.list_path)
        os.remove(list_path2)

    def _row_to_backup(self, row):
        """Convenience function

        :param list row: csv file row 'idx', 'cert_path', 'key_path'

        :returns: tuple of the form ('backup_cert_path', 'backup_key_path')
        :rtype: tuple

        """
        return (self._get_backup(self.config.cert_key_backup, row[0], row[1]),
                self._get_backup(self.config.cert_key_backup, row[0], row[2]))

    @classmethod
    def store_cert_key(cls, cert_path, key_path, config):
        """Store certificate key. (Used to allow quick revocation)

        :param str cert_path: Path to a certificate file.
        :param str key_path: Path to authorized key for certificate

        :ivar config: Configuration.
        :type config: :class:`~letsencrypt.client.interfaces.IConfig`

        """
        list_path = os.path.join(config.cert_key_backup, "LIST")
        le_util.make_or_verify_dir(config.cert_key_backup, 0o700, os.geteuid())

        cls._catalog_files(
            config.cert_key_backup, cert_path, key_path, list_path)

    @classmethod
    def _catalog_files(cls, backup_dir, cert_path, key_path, list_path):
        idx = 0
        if os.path.isfile(list_path):
            with open(list_path, "r+b") as csvfile:
                csvreader = csv.reader(csvfile)

                # Find the highest index in the file
                for row in csvreader:
                    idx = int(row[0]) + 1
                csvwriter = csv.writer(csvfile)
                # You must move the files before appending the row
                cls._copy_files(backup_dir, idx, cert_path, key_path)
                csvwriter.writerow([str(idx), cert_path, key_path])

        else:
            with open(list_path, "wb") as csvfile:
                csvwriter = csv.writer(csvfile)
                # You must move the files before appending the row
                cls._copy_files(backup_dir, idx, cert_path, key_path)
                csvwriter.writerow([str(idx), cert_path, key_path])

    @classmethod
    def _copy_files(cls, backup_dir, idx, cert_path, key_path):
        """Copies the files into the backup dir appropriately."""
        shutil.copy2(cert_path, cls._get_backup(backup_dir, idx, cert_path))
        shutil.copy2(key_path, cls._get_backup(backup_dir, idx, key_path))

    @classmethod
    def _get_backup(cls, backup_dir, idx, orig_path):
        """Returns the path to the backup."""
        return os.path.join(
            backup_dir, "{name}_{idx}".format(
                name=os.path.basename(orig_path), idx=str(idx)))


class Cert(object):
    """Cert object used for Revocation convenience.

    :ivar cert: M2Crypto X509 cert
    :type cert: :class:`M2Crypto.X509`

    :ivar int idx: convenience index used for listing
    :ivar orig: (`str` path - original certificate, `str` status)
    :type orig: :class:`PathStatus`
    :ivar orig_key: (`str` path - original auth key, `str` status)
    :type orig_key: :class:`PathStatus`
    :ivar str backup_path: backup filepath of the certificate
    :ivar str backup_key_path: backup filepath of the authorized key

    :ivar list installed: `list` of `str` describing all locations the cert
        is installed

    """
    PathStatus = collections.namedtuple("PathStatus", "path status")
    """Convenience container to hold path and status info"""

    DELETED_MSG = "This file has been moved or deleted"
    CHANGED_MSG = "This file has changed"

    def __init__(self, cert_path):
        """Cert initialization

        :param str cert_filepath: Name of file containing certificate in
            PEM format.

        """
        try:
            self.cert = M2Crypto.X509.load_cert(cert_path)
        except (IOError, M2Crypto.X509.X509Error):
            raise errors.LetsEncryptRevokerError(
                "Error loading certificate: %s" % cert_path)

        self.idx = -1

        self.orig = None
        self.orig_key = None
        self.backup_path = ""
        self.backup_key_path = ""

        self.installed = ["Unknown"]

    @classmethod
    def fromrow(cls, row, backup_dir):
        # pylint: disable=protected-access
        """Initialize Cert from a csv row."""
        idx = int(row[0])
        backup = Revoker._get_backup(backup_dir, idx, row[1])
        backup_key = Revoker._get_backup(backup_dir, idx, row[2])

        obj = cls(backup)
        obj.add_meta(idx, row[1], row[2], backup, backup_key)
        return obj

    def get_row(self):
        """Returns a list in CSV format. If meta data is available."""
        if self.orig is not None and self.orig_key is not None:
            return [str(self.idx), self.orig.path, self.orig_key.path]
        return None

    def add_meta(self, idx, orig, orig_key, backup, backup_key):
        """Add meta data to cert

        :param int idx: convenience index for revoker
        :param tuple orig: (`str` original certificate filepath, `str` status)
        :param tuple orig_key: (`str` original auth key path, `str` status)
        :param str backup: backup certificate filepath
        :param str backup_key: backup key filepath

        """
        status = ""
        key_status = ""

        # Verify original cert path
        if not os.path.isfile(orig):
            status = Cert.DELETED_MSG
        else:
            o_cert = M2Crypto.X509.load_cert(orig)
            if self.get_fingerprint() != o_cert.get_fingerprint(md="sha1"):
                status = Cert.CHANGED_MSG

        # Verify original key path
        if not os.path.isfile(orig_key):
            key_status = Cert.DELETED_MSG
        else:
            with open(orig_key, "r") as fd:
                key_pem = fd.read()
            with open(backup_key, "r") as fd:
                backup_key_pem = fd.read()
            if key_pem != backup_key_pem:
                key_status = Cert.CHANGED_MSG

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
        text.append("SHA1: %s%s" % (self.get_fingerprint(), os.linesep))
        text.append("Installed: %s" % self.get_installed_msg())

        if self.orig is not None:
            if self.orig.status == "":
                text.append("Path: %s" % self.orig.path)
            else:
                text.append("Orig Path: %s (%s)" % self.orig)
        if self.orig_key is not None:
            if self.orig_key.status == "":
                text.append("Auth Key Path: %s" % self.orig_key.path)
            else:
                text.append("Orig Auth Key Path: %s (%s)" % self.orig_key)

        text.append("")
        return os.linesep.join(text)

    def pretty_print(self):
        """Nicely frames a cert str"""
        frame = "-" * (display_util.WIDTH - 4) + os.linesep
        return "{frame}{cert}{frame}".format(frame=frame, cert=str(self))

    def __eq__(self, other):
        return self.cert.as_der() == other.cert.as_der()
