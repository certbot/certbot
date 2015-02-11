"""Revoker module to enable LE revocations."""
import csv
import logging
import os
import shutil

import M2Crypto
import zope.component

from letsencrypt.client import acme
from letsencrypt.client import crypto_util
from letsencrypt.client import display
from letsencrypt.client import interfaces
from letsencrypt.client import network


class Revoker(object):
    """A revocation class for LE.

    :ivar config: Configuration.
    :type config: :class:`letsencrypt.client.interfaces.IConfig`

    """

    def __init__(self, installer, config):
        self.network = network.Network(config.server)
        self.installer = installer
        self.config = config

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

        zope.component.getUtility(interfaces.IDisplay).generic_notification(
            "You have successfully revoked the certificate for "
            "%s" % cert["cn"])

        self.remove_cert_key(cert)
        self.list_certs_keys()

        return revocation

    def list_certs_keys(self):
        """List trusted Let's Encrypt certificates."""
        list_file = os.path.join(self.config.cert_key_backup, "LIST")
        certs = []

        if not os.path.isfile(list_file):
            logging.info(
                "You don't have any certificates saved from letsencrypt")
            return

        c_sha1_vh = {}
        for (cert, _, path) in self.installer.get_all_certs_keys():
            try:
                c_sha1_vh[M2Crypto.X509.load_cert(
                    cert).get_fingerprint(md="sha1")] = path
            except M2Crypto.X509.X509Error:
                continue

        with open(list_file, "rb") as csvfile:
            csvreader = csv.reader(csvfile)
            for row in csvreader:
                cert = crypto_util.get_cert_info(row[1])

                b_k = os.path.join(self.config.cert_key_backup,
                                   os.path.basename(row[2]) + "_" + row[0])
                b_c = os.path.join(self.config.cert_key_backup,
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
            zope.component.getUtility(interfaces.IDisplay).generic_notification(
                "There are not any trusted Let's Encrypt "
                "certificates for this server.")

    def choose_certs(self, certs):
        """Display choose certificates menu.

        :param list certs: List of cert dicts.

        """
        displayer = zope.component.getUtility(interfaces.IDisplay)
        code, tag = displayer.display_certs(certs)

        if code == display.OK:
            cert = certs[tag]
            if displayer.confirm_revocation(cert):
                self.acme_revocation(cert)
            else:
                self.choose_certs(certs)
        elif code == display.HELP:
            cert = certs[tag]
            displayer.more_info_cert(cert)
            self.choose_certs(certs)
        else:
            exit(0)

    def remove_cert_key(self, cert):  # pylint: disable=no-self-use
        """Remove certificate and key.

        :param dict cert: Cert dict used throughout revocation

        """
        list_file = os.path.join(self.config.cert_key_backup, "LIST")
        list_file2 = os.path.join(self.config.cert_key_backup, "LIST.tmp")

        with open(list_file, "rb") as orgfile:
            csvreader = csv.reader(orgfile)

            with open(list_file2, "wb") as newfile:
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
