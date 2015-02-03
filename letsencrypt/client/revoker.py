"""Revoker module to enable LE revocations."""
import collections
import csv
import logging
import os
import shutil

import M2Crypto
import zope.component

from letsencrypt.client import acme
from letsencrypt.client import CONFIG
from letsencrypt.client import display
from letsencrypt.client import interfaces
from letsencrypt.client import network


class Revoker(object):
    """A revocation class for LE."""
    def __init__(self, server, installer):
        self.network = network.Network(server)
        self.installer = installer
        self.displayer = zope.component.getUtility(interfaces.IDisplay)

    def acme_revocation(self, cert):
        """Handle ACME "revocation" phase.

        :param dict cert: TODO

        :returns: ACME "revocation" message.
        :rtype: dict

        """
        cert_der = M2Crypto.X509.load_cert(cert["backup_cert_file"]).as_der()
        with open(cert["backup_key_file"], "rU") as backup_key_file:
            key = backup_key_file.read()

        revocation = self.network.send_and_receive_expected(
            acme.revocation_request(cert_der, key), "revocation")

        self.displayer.notification(
            "You have successfully revoked the certificate for "
            "%s" % cert["cn"])

        self.remove_cert_key(cert)
        self.list_certs_keys()

        return revocation

    def list_certs_keys(self):
        """List trusted Let's Encrypt certificates."""
        list_file = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST")
        certs = []

        if not os.path.isfile(list_file):
            logging.info(
                "You don't have any certificates saved from letsencrypt")
            return

        csha1_vhlist = self._get_installed_locations()

        with open(list_file, "rb") as csvfile:
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
                if self.installer is not None:
                    cert.installed = csha1_vhlist.get(
                        cert.get_fingerprint, [])

                certs.append(cert)
        if certs:
            self._insert_installed_status(certs)
            self.choose_certs(certs)
        else:
            self.displayer.notification(
                "There are not any trusted Let's Encrypt "
                "certificates for this server.")

    def _get_installed_locations(self):
        """Get installed locations of certificates"""
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

    def choose_certs(self, certs):
        """Display choose certificates menu.

        :param list certs: List of cert dicts.

        """
        code, tag = self.display_certs(certs)

        if code == display.OK:
            cert = certs[tag]
            if self.confirm_revocation(cert):
                self.acme_revocation(cert)
            else:
                self.choose_certs(certs)
        elif code == display.HELP:
            cert = certs[tag]
            self.displayer.more_info_cert(cert)
            self.choose_certs(certs)
        else:
            exit(0)

    def remove_cert_key(self, cert):  # pylint: disable=no-self-use
        """Remove certificate and key.

        :param cert: Cert dict used throughout revocation

        """
        list_file = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST")
        list_file2 = os.path.join(CONFIG.CERT_KEY_BACKUP, "LIST.tmp")

        with open(list_file, "rb") as orgfile:
            csvreader = csv.reader(orgfile)

            with open(list_file2, "wb") as newfile:
                csvwriter = csv.writer(newfile)

                for row in csvreader:
                    if not (row[0] == str(cert.idx) and
                            row[1] == cert.orig.path and
                            row[2] == cert.orig_key.path):
                        csvwriter.writerow(row)

        shutil.copy2(list_file2, list_file)
        os.remove(list_file2)
        os.remove(cert["backup_cert_file"])
        os.remove(cert["backup_key_file"])

    def display_certs(self, certs):
        """Display the certificates in a menu for revocation.

        :param list certs: `list` of :class:`letsencrypt.client.

        :returns: tuple of the form (code, selection) where
            code is a display exit code
            selection is the user's int selection
        :rtype: tuple

        """
        list_choices = [
            ("%s | %s | %s" %
            (str(cert.get_cn().ljust(display.WIDTH - 39)),
            cert.get_not_before().strftime("%m-%d-%y"),
            "Installed" if cert.installed and cert.installed != ["Unknown"]
            else "")
            for cert in enumerate(certs))
        ]

        code, tag = self.displayer.menu(
            "Which certificates would you like to revoke?",
            "Revoke number (c to cancel): ",
            choices=list_choices, help_button=True,
            help_label="More Info", ok_label="Revoke")
        if not tag:
            tag = -1

        return code, (int(tag) - 1)

    def confirm_revocation(self, cert):
        """Confirm revocation screen.

        :param cert: certificate object
        :type cert: :class:

        :returns: True if user would like to revoke, False otherwise
        :rtype: bool

        """
        text = ("{0}Are you sure you would like to revoke the following "
                "certificate:{0}".format(os.linesep))
        text += cert.pretty_print()
        text += "This action cannot be reversed!"
        return display.OK == self.dialog.yesno(
            text, width=self.width, height=self.height)

    def more_info_cert(self, cert):
        """Displays more info about the cert.

        :param dict cert: cert dict used throughout revoker.py

        """
        text = "{0}Certificate Information:{0}".format(os.linesep)
        text += cert.pretty_print()
        self.notification(text, height=self.height)


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

    def __init__(self, cert_filepath):
        """Cert initialization

        :param str cert_filepath: Name of file containing certificate in
            PEM format.

        """
        try:
            self.cert = M2Crypto.X509.load_cert(cert_filepath)
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
        DELETED_MSG = "This file has been moved or deleted"
        CHANGED_MSG = "This file has changed"
        status = ""
        key_status = ""

        # Verify original cert path
        if not os.path.isfile(orig):
            status = DELETED_MSG
        else:
            o_cert = M2Crypto.X509.load_cert(orig)
            if self.get_fingerprint() != o_cert.get_fingerprint(md="sha1"):
                status = CHANGED_MSG

        # Verify original key path
        if not os.path.isfile(orig_key):
            key_status = DELETED_MSG
        else:
            with open(orig_key, "r") as fd:
                key_pem = fd.read()
            with open(backup_key, "r") as fd:
                backup_key_pem = fd.read()
            if key_pem != backup_key_pem:
                key_status = CHANGED_MSG

        self.idx = idx
        self.orig = Cert.PathStatus(orig, status)
        self.orig_key = Cert.PathStatus(orig_key, key_status)
        self.backup_path = backup
        self.backup_key_path = backup_key

    def get_installed_msg(self):
        return ", ".join(self.installed)

    def get_subject(self):
        return self.cert.get_subject().as_text()

    def get_cn(self):
        return self.cert.get_subject().CN

    def get_issuer(self):
        return self.cert.get_issuer().as_text()

    def get_fingerprint(self):
        return self.cert.get_fingerprint(md="sha1")

    def get_not_before(self):
        return self.cert.get_not_before().get_datetime()

    def get_not_after(self):
        return self.cert.get_not_after().get_datetime()

    def get_serial(self):
        self.cert.get_serial_number()

    def get_pub_key(self):
        # .. todo:: M2Crypto doesn't support ECC, this will have to be updated
        return "RSA " + str(self.cert.get_pubkey().size() * 8)

    def get_san(self):
        try:
            return self.cert.get_ext("subjectAltName").get_value()
        except LookupError:
            return ""

    def __str__(self):
        """Turn a Certinto a string."""
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
        text = "-" * (display.WIDTH - 4) + os.linesep
        text += str(self)
        text += "-" * (display.WIDTH - 4)
        return text

