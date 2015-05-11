import configobj
import copy
import datetime
import os
import OpenSSL
import parsedatetime
import pyrfc3339
import pytz
import re
import time

from letsencrypt.client import le_util

DEFAULTS = configobj.ConfigObj("renewal.conf")
DEFAULTS["renewal_configs_dir"] = "/tmp/etc/letsencrypt/configs"
DEFAULTS["official_archive_dir"] = "/tmp/etc/letsencrypt/archive"
DEFAULTS["live_dir"] = "/tmp/etc/letsencrypt/live"
ALL_FOUR = ("cert", "privkey", "chain", "fullchain")

def parse_time_interval(interval, textparser=parsedatetime.Calendar()):
    """Parse the time specified time interval, which can be in the
    English-language format understood by parsedatetime, e.g., '10 days',
    '3 weeks', '6 months', '9 hours', or a sequence of such intervals
    like '6 months 1 week' or '3 days 12 hours'.  If an integer is found
    with no associated unit, it is interpreted by default as a number of
    days."""
    if interval.strip().isdigit():
        interval += " days"
    return datetime.timedelta(0, time.mktime(textparser.parse(
        interval, time.localtime(0))[0]))

class RenewableCert(object):  # pylint: disable=too-many-instance-attributes
    """Represents a lineage of certificates that is under the management
    of the Let's Encrypt client, indicated by the existence of an
    associated renewal configuration file."""

    def __init__(self, configfile, defaults=DEFAULTS):
        if isinstance(configfile, str):
            if not os.path.exists(configfile):
                raise ValueError(
                    "renewal config file {0} doesn't exist".format(configfile))
            if not configfile.endswith(".conf"):
                raise ValueError("renewal config file name must end in .conf")
            self.lineagename = os.path.basename(configfile)[:-5]
            self.configfilename = os.path.basename(configfile)
        elif isinstance(configfile, configobj.ConfigObj):
            self.lineagename = os.path.basename(configfile.filename)[:-5]
            self.configfilename = os.path.basename(configfile.filename)
        else:
            raise TypeError("RenewableCert config must be file path "
                            "or ConfigObj object")

        # self.configuration should be used to read parameters that
        # may have been chosen based on default values from the
        # systemwide renewal configuration; self.configfile should be
        # used to make and save changes.
        self.configuration = copy.deepcopy(defaults)
        self.configfile = configobj.ConfigObj(configfile)
        self.configuration.merge(self.configfile)

        if not all(self.configuration.has_key(x) for x in ALL_FOUR):
            raise ValueError("renewal config file {0} is missing a required "
                             "file reference".format(configfile))

        self.cert = self.configuration["cert"]
        self.privkey = self.configuration["privkey"]
        self.chain = self.configuration["chain"]
        self.fullchain = self.configuration["fullchain"]

    def consistent(self):
        """Is the structure of the archived files and links related to this
        lineage correct and self-consistent?"""
        # Each element must be referenced with an absolute path
        if any(not os.path.isabs(x) for x in
               (self.cert, self.privkey, self.chain, self.fullchain)):
            return False
        # Each element must exist and be a symbolic link
        if any(not os.path.islink(x) for x in
               (self.cert, self.privkey, self.chain, self.fullchain)):
            return False
        for kind in ALL_FOUR:
            link = self.__getattribute__(kind)
            where = os.path.dirname(link)
            target = os.readlink(link)
            if not os.path.isabs(target):
                target = os.path.join(where, target)
            # Each element's link must point within the cert lineage's
            # directory within the official archive directory
            desired_directory = os.path.join(
                self.configuration["official_archive_dir"], self.lineagename)
            if not os.path.samefile(os.path.dirname(target),
                                    desired_directory):
                return False
            # The link must point to a file that exists
            if not os.path.exists(target):
                return False
            # The link must point to a file that follows the archive
            # naming convention
            pattern = re.compile(r"^{0}([0-9]+)\.pem$".format(kind))
            if not pattern.match(os.path.basename(target)):
                return False
            # It is NOT required that the link's target be a regular
            # file (it may itself be a symlink). But we should probably
            # do a recursive check that ultimately the target does
            # exist?
        # XXX: Additional possible consistency checks (e.g.
        #      cryptographic validation of the chain being a chain,
        #      the chain matching the cert, and the cert matching
        #      the subject key)
        # XXX: All four of the targets are in the same directory
        #      (This check is redundant with the check that they
        #      are all in the desired directory!)
        # len(set(os.path.basename(self.current_target(x)
        # for x in ALL_FOUR))) == 1
        return True

    def fix(self):
        """Attempt to fix some kinds of defects or inconsistencies
        in the symlink structure, if possible."""
        # TODO: Figure out what kinds of fixes are possible.  For
        #       example, checking if there is a valid version that
        #       we can update the symlinks to.  (Maybe involve
        #       parsing keys and certs to see if they exist and
        #       if a key corresponds to the subject key of a cert?)

    # TODO: In general, the symlink-reading functions below are not
    #       cautious enough about the possibility that links or their
    #       targets may not exist.  (This shouldn't happen, but might
    #       happen as a result of random tampering by a sysadmin, or
    #       filesystem errors, or crashes.)

    def current_target(self, kind):
        """Returns the full path to which the link of the specified
        kind currently points."""
        if kind not in ALL_FOUR:
            raise ValueError("unknown kind of item")
        link = self.__getattribute__(kind)
        if not os.path.exists(link):
            return None
        target = os.readlink(link)
        if not os.path.isabs(target):
            target = os.path.join(os.path.dirname(link), target)
        return target

    def current_version(self, kind):
        """Returns the numerical version of the object to which the link
        of the specified kind currently points. For example, if kind
        is "chain" and the current chain link points to a file named
        "chain7.pem", returns the integer 7."""
        if kind not in ALL_FOUR:
            raise ValueError("unknown kind of item")
        pattern = re.compile(r"^{0}([0-9]+)\.pem$".format(kind))
        target = self.current_target(kind)
        if not target or not os.path.exists(target):
            target = ""
        matches = pattern.match(os.path.basename(target))
        if matches:
            return int(matches.groups()[0])
        else:
            return None

    def version(self, kind, version):
        """Constructs the filename that would correspond to the
        specified version of the specified kind of item in this
        lineage.  Warning: the specified version may not exist."""
        if kind not in ALL_FOUR:
            raise ValueError("unknown kind of item")
        where = os.path.dirname(self.current_target(kind))
        return os.path.join(where, "{0}{1}.pem".format(kind, version))

    def available_versions(self, kind):
        """Which alternative versions of the specified kind of item
        exist in the archive directory where the current version is
        stored?"""
        if kind not in ALL_FOUR:
            raise ValueError("unknown kind of item")
        where = os.path.dirname(self.current_target(kind))
        files = os.listdir(where)
        pattern = re.compile(r"^{0}([0-9]+)\.pem$".format(kind))
        matches = [pattern.match(f) for f in files]
        return sorted([int(m.groups()[0]) for m in matches if m])

    def newest_available_version(self, kind):
        """What is the newest available version of the specified
        kind of item?"""
        return max(self.available_versions(kind))

    def latest_common_version(self):
        """What is the largest version number for which versions
        of cert, privkey, chain, and fullchain are all available?"""
        # TODO: this can raise ValueError if there is no version overlap
        #       (it should probably return None instead)
        # TODO: this can raise a spurious AttributeError if the current
        #       link for any kind is missing (it should probably return None)
        versions = [self.available_versions(x) for x in ALL_FOUR]
        return max(n for n in versions[0] if all(n in v for v in versions[1:]))

    def next_free_version(self):
        """What is the smallest new version number that is larger than
        any available version of any managed item?"""
        # TODO: consider locking/mutual exclusion between updating processes
        # This isn't self.latest_common_version() + 1 because we don't want
        # collide with a version that might exist for one file type but not
        # for the others.
        return max(self.newest_available_version(x) for x in ALL_FOUR) + 1

    def has_pending_deployment(self):
        """Is there a later version of all of the managed items?"""
        # TODO: consider whether to assume consistency or treat
        #       inconsistent/consistent versions differently
        smallest_current = min(self.current_version(x) for x in ALL_FOUR)
        return smallest_current < self.latest_common_version()

    def update_link_to(self, kind, version):
        """Change the target of the link of the specified item to point
        to the specified version. (Note that this method doesn't verify
        that the specified version exists.)"""
        if kind not in ALL_FOUR:
            raise ValueError("unknown kind of item")
        link = self.__getattribute__(kind)
        filename = "{0}{1}.pem".format(kind, version)
        # Relative rather than absolute target directory
        target_directory = os.path.dirname(os.readlink(link))
        # TODO: it could be safer to make the link first under a temporary
        #       filename, then unlink the old link, then rename the new link
        #       to the old link; this ensures that this process is able to
        #       create symlinks.
        # TODO: we might also want to check consistency of related links
        #       for the other corresponding items
        os.unlink(link)
        os.symlink(os.path.join(target_directory, filename), link)

    def update_all_links_to(self, version):
        """Change the target of the cert, privkey, chain, and fullchain links
        to point to the specified version."""
        for kind in ALL_FOUR:
            self.update_link_to(kind, version)

    def notbefore(self, version=None):
        """When is the beginning validity time of the specified version of the
        cert in this lineage?  (If no version is specified, use the current
        version.)"""
        if version == None:
            target = self.current_target("cert")
        else:
            target = self.version("cert", version)
        pem = open(target).read()
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                               pem)
        i = x509.get_notBefore()
        return pyrfc3339.parse(i[0:4] + "-" + i[4:6] + "-" + i[6:8] + "T" +
                               i[8:10] + ":" + i[10:12] +":" +i[12:])

    def notafter(self, version=None):
        """When is the ending validity time of the specified version of the
        cert in this lineage?  (If no version is specified, use the current
        version.)"""
        if version == None:
            target = self.current_target("cert")
        else:
            target = self.version("cert", version)
        pem = open(target).read()
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                               pem)
        i = x509.get_notAfter()
        return pyrfc3339.parse(i[0:4] + "-" + i[4:6] + "-" + i[6:8] + "T" +
                               i[8:10] + ":" + i[10:12] +":" +i[12:])

    def should_autodeploy(self):
        """Should this certificate lineage be updated automatically to
        point to an existing pending newer version? (Considers whether
        autodeployment is enabled, whether a relevant newer version
        exists, and whether the time interval for autodeployment has
        been reached.)"""
        if (not self.configuration.has_key("autodeploy") or
                self.configuration.as_bool("autodeploy")):
            if self.has_pending_deployment():
                interval = self.configuration.get("deploy_before_expiry",
                                                  "5 days")
                autodeploy_interval = parse_time_interval(interval)
                expiry = self.notafter()
                now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
                remaining = expiry - now
                if remaining < autodeploy_interval:
                    return True
        return False

    def ocsp_revoked(self, version=None):
        # pylint: disable=no-self-use,unused-argument
        """Is the specified version of this certificate lineage revoked
        according to OCSP or intended to be revoked according to Let's
        Encrypt OCSP extensions? (If no version is specified, use the
        current version.)"""
        # XXX: This query and its associated network service aren't
        # implemented yet, so we currently return False (indicating that the
        # certificate is not revoked).
        return False

    def should_autorenew(self):
        """Should an attempt be made to automatically renew the most
        recent certificate in this certificate lineage right now?"""
        if (not self.configuration.has_key("autorenew")
                or self.configuration.as_bool("autorenew")):
            # Consider whether to attempt to autorenew this cert now
            # XXX: both self.ocsp_revoked() and self.notafter() are bugs
            #      here because we should be looking at the latest version, not
            #      the current version!
            # Renewals on the basis of revocation
            if self.ocsp_revoked():
                return True
            # Renewals on the basis of expiry time
            interval = self.configuration.get("renew_before_expiry", "10 days")
            autorenew_interval = parse_time_interval(interval)
            expiry = self.notafter()
            now = datetime.datetime.utcnow().replace(tzinfo=pytz.UTC)
            remaining = expiry - now
            if remaining < autorenew_interval:
                return True
            return False

    @classmethod
    def new_lineage(cls, lineagename, cert, privkey, chain,
                    renewalparams=None, config=DEFAULTS):
        # pylint: disable=too-many-locals
        """Create a new certificate lineage with the (suggested) lineage name
        lineagename, and the associated cert, privkey, and chain (the
        associated fullchain will be created automatically).  Optional
        configurator and renewalparams record the configuration that was
        originally used to obtain this cert, so that it can be reused later
        during automated renewal.

        Returns a new RenewableCert object referring to the created
        lineage. (The actual lineage name, as well as all the relevant
        file paths, will be available within this object.)"""
        configs_dir = config["renewal_configs_dir"]
        archive_dir = config["official_archive_dir"]
        live_dir = config["live_dir"]
        for i in (configs_dir, archive_dir, live_dir):
            if not os.path.exists(i):
                os.makedirs(i, 0700)
        config_file, config_filename = le_util.unique_lineage_name(configs_dir,
                                                                   lineagename)
        if not config_filename.endswith(".conf"):
            raise ValueError("renewal config file name must end in .conf")
        # lineagename will now potentially be modified based on what
        # renewal configuration file could actually be created
        lineagename = os.path.basename(config_filename)[:-5]
        archive = os.path.join(archive_dir, lineagename)
        live_dir = os.path.join(live_dir, lineagename)
        if os.path.exists(archive):
            raise ValueError("archive directory exists for " + lineagename)
        if os.path.exists(live_dir):
            raise ValueError("live directory exists for " + lineagename)
        os.mkdir(archive)
        os.mkdir(live_dir)
        relative_archive = os.path.join("..", "..", "archive", lineagename)
        cert_target = os.path.join(live_dir, "cert.pem")
        privkey_target = os.path.join(live_dir, "privkey.pem")
        chain_target = os.path.join(live_dir, "chain.pem")
        fullchain_target = os.path.join(live_dir, "fullchain.pem")
        os.symlink(os.path.join(relative_archive, "cert1.pem"),
                   cert_target)
        os.symlink(os.path.join(relative_archive, "privkey1.pem"),
                   privkey_target)
        os.symlink(os.path.join(relative_archive, "chain1.pem"),
                   chain_target)
        os.symlink(os.path.join(relative_archive, "fullchain1.pem"),
                   fullchain_target)
        with open(cert_target, "w") as f:
            f.write(cert)
        with open(privkey_target, "w") as f:
            f.write(privkey)
            # XXX: Let's make sure to get the file permissions right here
        with open(chain_target, "w") as f:
            f.write(chain)
        with open(fullchain_target, "w") as f:
            f.write(cert + chain)
        config_file.close()
        new_config = configobj.ConfigObj(config_filename, create_empty=True)
        new_config["cert"] = cert_target
        new_config["privkey"] = privkey_target
        new_config["chain"] = chain_target
        new_config["fullchain"] = fullchain_target
        if renewalparams:
            new_config["renewalparams"] = renewalparams
            new_config.comments["renewalparams"] = ["",
                                                    "Options and defaults used"
                                                    " in the renewal process"]
        # TODO: add human-readable comments explaining other available
        #       parameters
        new_config.write()
        return cls(new_config, config)

    def save_successor(self, prior_version, new_cert, new_privkey, new_chain):
        """Save a new cert and chain as a successor of a specific prior
        version in this lineage.  Returns the new version number that was
        created.  Note: does NOT update links to deploy this version."""
        # XXX: assumes official archive location rather than examining links
        # XXX: consider using os.open for availablity of os.O_EXCL
        # XXX: ensure file permissions are correct; also create directories
        #      if needed (ensuring their permissions are correct)
        target_version = self.next_free_version()
        archive = self.configuration["official_archive_dir"]
        prefix = os.path.join(archive, self.lineagename)
        cert_target = os.path.join(
            prefix, "cert{0}.pem".format(target_version))
        privkey_target = os.path.join(
            prefix, "privkey{0}.pem".format(target_version))
        chain_target = os.path.join(
            prefix, "chain{0}.pem".format(target_version))
        fullchain_target = os.path.join(
            prefix, "fullchain{0}.pem".format(target_version))
        with open(cert_target, "w") as f:
            f.write(new_cert)
        if new_privkey is None:
            # The behavior below keeps the prior key by creating a new
            # symlink to the old key or the target of the old key symlink.
            old_privkey = os.path.join(
                prefix, "privkey{0}.pem".format(prior_version))
            if os.path.islink(old_privkey):
                old_privkey = os.readlink(old_privkey)
            else:
                old_privkey = "privkey{0}.pem".format(prior_version)
            os.symlink(old_privkey, privkey_target)
        else:
            with open(privkey_target, "w") as f:
                f.write(new_privkey)
        with open(chain_target, "w") as f:
            f.write(new_chain)
        with open(fullchain_target, "w") as f:
            f.write(new_cert + new_chain)
        return target_version
