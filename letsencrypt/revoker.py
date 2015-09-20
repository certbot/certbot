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
import tempfile

import OpenSSL

from acme import client as acme_client
from acme import crypto_util as acme_crypto_util
from acme.jose import util as jose_util

from letsencrypt import crypto_util
from letsencrypt import errors
from letsencrypt import le_util

from letsencrypt.display import util as display_util
from letsencrypt.display import revocation


logger = logging.getLogger(__name__)


class Revoker(object):
    """A revocation class for LE.

    .. todo:: Add a method to specify your own certificate for revocation - CLI

    :ivar .acme.client.Client acme: ACME client

    :ivar installer: Installer object
    :type installer: :class:`~letsencrypt.interfaces.IInstaller`

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.interfaces.IConfig`

    :ivar bool no_confirm: Whether or not to ask for confirmation for revocation

    """
    def __init__(self, installer, config, no_confirm=False):
        # XXX
        self.acme = acme_client.Client(directory=None, key=None, alg=None)

        self.installer = installer
        self.config = config
        self.no_confirm = no_confirm

        le_util.make_or_verify_dir(config.cert_key_backup, 0o700, os.geteuid(),
                                   self.config.strict_permissions)

        # TODO: Find a better solution for this...
        self.list_path = os.path.join(config.cert_key_backup, "LIST")
        # Make sure that the file is available for use for rest of class
        open(self.list_path, "a").close()

    def revoke_from_key(self, authkey):
        """Revoke all certificates under an authorized key.

        :param authkey: Authorized key used in previous transactions
        :type authkey: :class:`letsencrypt.le_util.Key`

        """
        certs = []
        try:
            clean_pem = OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.load_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM, authkey.pem))
        except OpenSSL.crypto.Error as error:
            logger.debug(error, exc_info=True)
            raise errors.RevokerError(
                "Invalid key file specified to revoke_from_key")

        with open(self.list_path, "rb") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                # idx, cert, key
                # Add all keys that match to marked list
                # Note: The key can be different than the pub key found in the
                #    certificate.
                _, b_k = self._row_to_backup(row)
                try:
                    test_pem = OpenSSL.crypto.dump_privatekey(
                        OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.load_privatekey(
                            OpenSSL.crypto.FILETYPE_PEM, open(b_k).read()))
                except OpenSSL.crypto.Error as error:
                    logger.debug(error, exc_info=True)
                    # This should never happen given the assumptions of the
                    # module. If it does, it is probably best to delete the
                    # the offending key/cert. For now... just raise an exception
                    raise errors.RevokerError("%s - backup file is corrupted.")

                if clean_pem == test_pem:
                    certs.append(
                        Cert.fromrow(row, self.config.cert_key_backup))
        if certs:
            self._safe_revoke(certs)
        else:
            logger.info("No certificates using the authorized key were found.")

    def revoke_from_cert(self, cert_path):
        """Revoke a certificate by specifying a file path.

        .. todo:: Add the ability to revoke the certificate even if the cert
            is not stored locally. A path to the auth key will need to be
            attained from the user.

        :param str cert_path: path to ACME certificate in pem form

        """
        # Locate the correct certificate (do not rely on filename)
        cert_to_revoke = Cert(cert_path)

        with open(self.list_path, "rb") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                cert = Cert.fromrow(row, self.config.cert_key_backup)

                if cert.get_der() == cert_to_revoke.get_der():
                    self._safe_revoke([cert])
                    return

        logger.info("Associated ACME certificate was not found.")

    def revoke_from_menu(self):
        """List trusted Let's Encrypt certificates."""

        csha1_vhlist = self._get_installed_locations()
        certs = self._populate_saved_certs(csha1_vhlist)

        while True:
            if certs:
                code, selection = revocation.display_certs(certs)

                if code == display_util.OK:
                    revoked_certs = self._safe_revoke([certs[selection]])
                    # Since we are currently only revoking one cert at a time...
                    if revoked_certs:
                        del certs[selection]
                elif code == display_util.HELP:
                    revocation.more_info_cert(certs[selection])
                else:
                    return
            else:
                logger.info(
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

        :param dict csha1_vhlist: map from cert sha1 fingerprints to a list
           of it's installed location paths.

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
        """Get installed locations of certificates.

        :returns: map from cert sha1 fingerprint to :class:`list` of vhosts
            where the certificate is installed.

        """
        csha1_vhlist = {}

        if self.installer is None:
            return csha1_vhlist

        for (cert_path, _, path) in self.installer.get_all_certs_keys():
            try:
                with open(cert_path) as cert_file:
                    cert_data = cert_file.read()
            except IOError:
                continue
            try:
                cert_obj, _ = crypto_util.pyopenssl_load_certificate(cert_data)
            except errors.Error:
                continue
            cert_sha1 = cert_obj.digest("sha1")
            if cert_sha1 in csha1_vhlist:
                csha1_vhlist[cert_sha1].append(path)
            else:
                csha1_vhlist[cert_sha1] = [path]

        return csha1_vhlist

    def _safe_revoke(self, certs):
        """Confirm and revoke certificates.

        :param certs: certs intended to be revoked
        :type certs: :class:`list` of :class:`letsencrypt.revoker.Cert`

        :returns: certs successfully revoked
        :rtype: :class:`list` of :class:`letsencrypt.revoker.Cert`

        """
        success_list = []
        try:
            for cert in certs:
                if self.no_confirm or revocation.confirm_revocation(cert):
                    try:
                        self._acme_revoke(cert)
                    except errors.Error:
                        # TODO: Improve error handling when networking is set...
                        logger.error(
                            "Unable to revoke cert:%s%s", os.linesep, str(cert))
                    success_list.append(cert)
                    revocation.success_revocation(cert)
        finally:
            if success_list:
                self._remove_certs_keys(success_list)

        return success_list

    def _acme_revoke(self, cert):
        """Revoke the certificate with the ACME server.

        :param cert: certificate to revoke
        :type cert: :class:`letsencrypt.revoker.Cert`

        :returns: TODO

        """
        # XXX | pylint: disable=unused-variable

        # pylint: disable=protected-access
        certificate = jose_util.ComparableX509(cert._cert)
        try:
            with open(cert.backup_key_path, "rU") as backup_key_file:
                key = OpenSSL.crypto.load_privatekey(
                    OpenSSL.crypto.FILETYPE_PEM, backup_key_file.read())
        # If the key file doesn't exist... or is corrupted
        except OpenSSL.crypto.Error as error:
            logger.debug(error, exc_info=True)
            raise errors.RevokerError(
                "Corrupted backup key file: %s" % cert.backup_key_path)

        return self.acme.revoke(cert=None)  # XXX

    def _remove_certs_keys(self, cert_list):  # pylint: disable=no-self-use
        """Remove certificate and key.

        :param list cert_list: Must contain certs, each is of type
            :class:`letsencrypt.revoker.Cert`

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
            :class:`letsencrypt.revoker.Cert`

        """
        _, list_path2 = tempfile.mkstemp(".tmp", "LIST")
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
            raise errors.RevokerError(
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
        :type config: :class:`~letsencrypt.interfaces.IConfig`

        """
        list_path = os.path.join(config.cert_key_backup, "LIST")
        le_util.make_or_verify_dir(config.cert_key_backup, 0o700, os.geteuid(),
                                   config.strict_permissions)

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

    :ivar _cert: Certificate
    :type _cert: :class:`OpenSSL.crypto.X509`

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
            with open(cert_path) as cert_file:
                cert_data = cert_file.read()
        except IOError:
            raise errors.RevokerError(
                "Error loading certificate: %s" % cert_path)

        try:
            self._cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert_data)
        except OpenSSL.crypto.Error:
            raise errors.RevokerError(
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
            with open(orig) as orig_file:
                orig_data = orig_file.read()
            o_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, orig_data)
            if self.get_fingerprint() != o_cert.digest("sha1"):
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

    def get_cn(self):
        """Get common name."""
        return self._cert.get_subject().CN

    def get_fingerprint(self):
        """Get SHA1 fingerprint."""
        return self._cert.digest("sha1")

    def get_not_before(self):
        """Get not_valid_before field."""
        return crypto_util.asn1_generalizedtime_to_dt(
            self._cert.get_notBefore())

    def get_not_after(self):
        """Get not_valid_after field."""
        return crypto_util.asn1_generalizedtime_to_dt(
            self._cert.get_notAfter())

    def get_der(self):
        """Get certificate in der format."""
        return OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, self._cert)

    def get_pub_key(self):
        """Get public key size.

        .. todo:: Support for ECC

        """
        return "RSA {0}".format(self._cert.get_pubkey().bits)

    def get_san(self):
        """Get subject alternative name if available."""
        # pylint: disable=protected-access
        return ", ".join(acme_crypto_util._pyopenssl_cert_or_req_san(self._cert))

    def __str__(self):
        text = [
            "Subject: %s" % crypto_util.pyopenssl_x509_name_as_text(
                self._cert.get_subject()),
            "SAN: %s" % self.get_san(),
            "Issuer: %s" % crypto_util.pyopenssl_x509_name_as_text(
                self._cert.get_issuer()),
            "Public Key: %s" % self.get_pub_key(),
            "Not Before: %s" % str(self.get_not_before()),
            "Not After: %s" % str(self.get_not_after()),
            "Serial Number: %s" % self._cert.get_serial_number(),
            "SHA1: %s%s" % (self.get_fingerprint(), os.linesep),
            "Installed: %s" % ", ".join(self.installed),
        ]

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
