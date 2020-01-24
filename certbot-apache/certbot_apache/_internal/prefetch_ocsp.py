"""A mixin class for OCSP response prefetching for Apache plugin"""
import logging
import shutil
import time

from acme.magic_typing import Dict  # pylint: disable=unused-import, no-name-in-module

from certbot import errors
from certbot._internal import ocsp
from certbot.plugins.enhancements import OCSPPrefetchEnhancement

from certbot.compat import filesystem
from certbot.compat import os
from certbot_apache._internal import apache_util
from certbot_apache._internal import constants

logger = logging.getLogger(__name__)

class OCSPPrefetchMixin(object):
    """OCSPPrefetchMixin implements OCSP response prefetching"""

    def __init__(self, *args, **kwargs):
        self._ocsp_prefetch = {}  # type: Dict[str, str]
        self._ocsp_dbm_bsddb = False
        # This is required because of python super() call chain.
        # Additionally, mypy isn't able to figure the chain out and needs to be
        # disabled for this line. See https://github.com/python/mypy/issues/5887
        super(OCSPPrefetchMixin, self).__init__(*args, **kwargs)  # type: ignore

    def _ensure_ocsp_dirs(self):
        """Makes sure that the OCSP directory paths exist."""
        ocsp_work = os.path.join(self.config.work_dir, "ocsp")
        ocsp_save = os.path.join(self.config.config_dir, "ocsp")
        for path in [ocsp_work, ocsp_save]:
            if not os.path.isdir(path):
                filesystem.makedirs(path)
                filesystem.chmod(path, 0o755)

    def _ensure_ocsp_prefetch_compatibility(self):
        """Make sure that the operating system supports the required libraries
        to manage Apache DBM files.

        :raises: errors.NotSupportedError
        """
        try:
            import bsddb  # pylint: disable=unused-variable
        except ImportError:
            import dbm
            if not hasattr(dbm, 'ndbm') or dbm.ndbm.library != 'Berkeley DB':  # pylint: disable=no-member
                msg = ("Unfortunately your operating system does not have a "
                       "compatible database module available for managing "
                       "Apache OCSP stapling cache database.")
                raise errors.NotSupportedError(msg)

    def _ocsp_dbm_open(self, filepath):
        """Helper method to open an DBM file in a way that depends on the platform
        that Certbot is run on. Returns an open database structure."""

        if not os.path.isfile(filepath+".db"):
            raise errors.PluginError(
                "The OCSP stapling cache DBM file wasn't created by Apache.")
        try:
            import bsddb
            self._ocsp_dbm_bsddb = True
            cache_path = filepath + ".db"
            try:
                database = bsddb.hashopen(cache_path, 'w')
            except Exception:
                raise errors.PluginError("Unable to open dbm database file.")
        except ImportError:
            # Python3 doesn't have bsddb module, so we use dbm.ndbm instead
            import dbm
            try:
                database = dbm.ndbm.open(filepath, 'w')  # pylint: disable=no-member
            except Exception:
                # This is raised if a file cannot be found
                raise errors.PluginError("Unable to open dbm database file.")
        return database

    def _ocsp_dbm_close(self, database):
        """Helper method to sync and close a DBM file, in a way required by the
        used dbm implementation."""
        if self._ocsp_dbm_bsddb:
            database.sync()
            database.close()
        else:
            database.close()

    def _ocsp_refresh_if_needed(self, pf_obj):
        """Refreshes OCSP response for a certiifcate if it's due

        :param dict pf_obj: OCSP prefetch object from pluginstorage

        :returns: If OCSP response was updated
        :rtype: bool

        """
        ttl = pf_obj["lastupdate"] + constants.OCSP_INTERNAL_TTL
        if ttl < time.time():
            self._ocsp_refresh(pf_obj["cert_path"], pf_obj["chain_path"])
            return True
        return False


    def _ocsp_refresh(self, cert_path, chain_path):
        """Refresh the OCSP response for a certificate

        :param str cert_path: Filesystem path to certificate file
        :param str chain_path: Filesystem path to certificate chain file

        """

        self._ensure_ocsp_dirs()
        ocsp_workfile = os.path.join(
            self.config.work_dir, "ocsp",
            apache_util.certid_sha1_hex(cert_path))
        handler = ocsp.RevocationChecker()
        if not handler.revoked(cert_path, chain_path, ocsp_workfile):
            # Guaranteed good response
            cache_path = os.path.join(self.config.config_dir, "ocsp", "ocsp_cache")
            # dbm.open automatically adds the file extension, it will be
            db = self._ocsp_dbm_open(cache_path)
            cert_sha = apache_util.certid_sha1(cert_path)
            db[cert_sha] = self._ocsp_response_dbm(ocsp_workfile)
            self._ocsp_dbm_close(db)
        else:
            logger.warning("Encountered an issue while trying to prefetch OCSP "
                           "response for certificate: %s", cert_path)

    def _ocsp_response_dbm(self, workfile):
        """Creates a dbm entry for OCSP response data

        :param str workfile: File path for raw OCSP response

        :returns: OCSP response cache data that Apache can use
        :rtype: string

        """

        with open(workfile, 'rb') as fh:
            response = fh.read()
        ttl = constants.OCSP_APACHE_TTL
        return apache_util.get_apache_ocsp_struct(ttl, response)

    def _ocsp_prefetch_save(self, cert_path, chain_path):
        """Saves status of current OCSP prefetch, including the last update
        time to determine if an update is needed on later run.

        :param str cert_path: Filesystem path to certificate
        :param str chain_path: Filesystem path to certificate chain file

        """
        status = {
            "lastupdate": time.time(),
            "cert_path": cert_path,
            "chain_path": chain_path
        }
        cert_id = apache_util.certid_sha1_hex(cert_path)
        self._ocsp_prefetch[cert_id] = status
        self.storage.put("ocsp_prefetch", self._ocsp_prefetch)
        self.storage.save()

    def _ocsp_prefetch_fetch_state(self):
        """
        Populates the OCSP prefetch state from the pluginstorage.
        """
        try:
            self._ocsp_prefetch = self.storage.fetch("ocsp_prefetch")
        except KeyError:
            self._ocsp_prefetch = dict()

    def _ocsp_prefetch_backup_db(self):
        """
        Copies the active dbm file to work directory.
        """
        self._ensure_ocsp_dirs()
        cache_path = os.path.join(self.config.config_dir, "ocsp", "ocsp_cache.db")
        try:
            shutil.copy2(cache_path, os.path.join(self.config.work_dir, "ocsp"))
        except IOError:
            logger.debug("Encountered an issue while trying to backup OCSP dbm file")

    def _ocsp_prefetch_restore_db(self):
        """
        Restores the active dbm file from work directory.
        """
        self._ensure_ocsp_dirs()
        cache_path = os.path.join(self.config.config_dir, "ocsp", "ocsp_cache.db")
        work_file_path = os.path.join(self.config.work_dir, "ocsp", "ocsp_cache.db")
        try:
            shutil.copy2(work_file_path, cache_path)
        except IOError:
            logger.debug("Encountered an issue when trying to restore OCSP dbm file")

    def enable_ocsp_prefetch(self, lineage, domains):
        """Enable OCSP Stapling and prefetching of the responses.

        In OCSP, each client (e.g. browser) would have to query the
        OCSP Responder to validate that the site certificate was not revoked.

        Enabling OCSP Stapling, would allow the web-server to query the OCSP
        Responder, and staple its response to the offered certificate during
        TLS. i.e. clients would not have to query the OCSP responder.

        """

        # Fail early if we are not able to support this
        self._ensure_ocsp_prefetch_compatibility()
        prefetch_vhosts = set()
        for domain in domains:
            matched_vhosts = self.choose_vhosts(domain, create_if_no_ssl=False)
            # We should be handling only SSL vhosts
            for vh in matched_vhosts:
                if vh.ssl:
                    prefetch_vhosts.add(vh)

        if prefetch_vhosts:
            for vh in prefetch_vhosts:
                self._enable_ocsp_stapling(vh, None, prefetch=True)
            self.restart()
            # Ensure Apache has enough time to properly restart and create the file
            time.sleep(2)
            try:
                self._ocsp_refresh(lineage.cert_path, lineage.chain_path)
                self._ocsp_prefetch_save(lineage.cert_path, lineage.chain_path)
                self.save("Enabled OCSP prefetching")
            except errors.PluginError as err:
                # Revert the OCSP prefetch configuration
                self.recovery_routine()
                self.restart()
                msg = ("Encountered an error while trying to enable OCSP prefetch "
                       "enhancement: %s.\nOCSP prefetch was not enabled.")
                raise errors.PluginError(msg % str(err))

    def update_ocsp_prefetch(self, _unused_lineage):
        """Checks all certificates that are managed by OCSP prefetch, and
        refreshes OCSP responses for them if required."""

        self._ocsp_prefetch_fetch_state()
        if not self._ocsp_prefetch:
            # No OCSP prefetching enabled for any certificate
            return

        for _, pf in self._ocsp_prefetch.items():
            if self._ocsp_refresh_if_needed(pf):
                # Save the status to pluginstorage
                self._ocsp_prefetch_save(pf["cert_path"], pf["chain_path"])

    def restart(self):
        """Runs a config test and reloads the Apache server.

        :raises .errors.MisconfigurationError: If either the config test
            or reload fails.

        """
        self.config_test()

        if not self._ocsp_prefetch:
            # Try to populate OCSP prefetch structure from pluginstorage
            self._ocsp_prefetch_fetch_state()
        if self._ocsp_prefetch:
            # OCSP prefetching is enabled, so back up the db
            self._ocsp_prefetch_backup_db()

        try:
            self._reload()
        except  errors.MisconfigurationError:
            self._ocsp_prefetch_restore_db()
            raise

        if self._ocsp_prefetch:
            # Restore the backed up dbm database
            self._ocsp_prefetch_restore_db()


OCSPPrefetchEnhancement.register(OCSPPrefetchMixin)  # pylint: disable=no-member
