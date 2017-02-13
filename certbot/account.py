"""Creates ACME accounts for server."""
import datetime
import hashlib
import logging
import os
import shutil
import socket

from cryptography.hazmat.primitives import serialization
import pyrfc3339
import pytz
import six
import zope.component

from acme import fields as acme_fields
from acme import jose
from acme import messages

from certbot import errors
from certbot import interfaces
from certbot import util


logger = logging.getLogger(__name__)


class Account(object):  # pylint: disable=too-few-public-methods
    """ACME protocol registration.

    :ivar .RegistrationResource regr: Registration Resource
    :ivar .JWK key: Authorized Account Key
    :ivar .Meta: Account metadata
    :ivar str id: Globally unique account identifier.

    """

    class Meta(jose.JSONObjectWithFields):
        """Account metadata

        :ivar datetime.datetime creation_dt: Creation date and time (UTC).
        :ivar str creation_host: FQDN of host, where account has been created.

        .. note:: ``creation_dt`` and ``creation_host`` are useful in
            cross-machine migration scenarios.

        """
        creation_dt = acme_fields.RFC3339Field("creation_dt")
        creation_host = jose.Field("creation_host")

    def __init__(self, regr, key, meta=None):
        self.key = key
        self.regr = regr
        self.meta = self.Meta(
            # pyrfc3339 drops microseconds, make sure __eq__ is sane
            creation_dt=datetime.datetime.now(
                tz=pytz.UTC).replace(microsecond=0),
            creation_host=socket.getfqdn()) if meta is None else meta

        self.id = hashlib.md5(
            self.key.key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        ).hexdigest()
        # Implementation note: Email? Multiple accounts can have the
        # same email address. Registration URI? Assigned by the
        # server, not guaranteed to be stable over time, nor
        # canonical URI can be generated. ACME protocol doesn't allow
        # account key (and thus its fingerprint) to be updated...

    @property
    def slug(self):
        """Short account identification string, useful for UI."""
        return "{1}@{0} ({2})".format(pyrfc3339.generate(
            self.meta.creation_dt), self.meta.creation_host, self.id[:4])

    def __repr__(self):
        return "<{0}({1})>".format(self.__class__.__name__, self.id)

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.key == other.key and self.regr == other.regr and
                self.meta == other.meta)


def report_new_account(config):
    """Informs the user about their new ACME account."""
    reporter = zope.component.queryUtility(interfaces.IReporter)
    if reporter is None:
        return
    reporter.add_message(
        "Your account credentials have been saved in your Certbot "
        "configuration directory at {0}. You should make a secure backup "
        "of this folder now. This configuration directory will also "
        "contain certificates and private keys obtained by Certbot "
        "so making regular backups of this folder is ideal.".format(
            config.config_dir),
        reporter.MEDIUM_PRIORITY)


class AccountMemoryStorage(interfaces.AccountStorage):
    """In-memory account strage."""

    def __init__(self, initial_accounts=None):
        self.accounts = initial_accounts if initial_accounts is not None else {}

    def find_all(self):
        return list(six.itervalues(self.accounts))

    def save(self, account):
        if account.id in self.accounts:
            logger.debug("Overwriting account: %s", account.id)
        self.accounts[account.id] = account

    def load(self, account_id):
        try:
            return self.accounts[account_id]
        except KeyError:
            raise errors.AccountNotFound(account_id)


class AccountFileStorage(interfaces.AccountStorage):
    """Accounts file storage.

    :ivar .IConfig config: Client configuration

    """
    def __init__(self, config):
        self.config = config
        util.make_or_verify_dir(config.accounts_dir, 0o700, os.geteuid(),
                                   self.config.strict_permissions)

    def _account_dir_path(self, account_id):
        return os.path.join(self.config.accounts_dir, account_id)

    @classmethod
    def _regr_path(cls, account_dir_path):
        return os.path.join(account_dir_path, "regr.json")

    @classmethod
    def _key_path(cls, account_dir_path):
        return os.path.join(account_dir_path, "private_key.json")

    @classmethod
    def _metadata_path(cls, account_dir_path):
        return os.path.join(account_dir_path, "meta.json")

    def find_all(self):
        try:
            candidates = os.listdir(self.config.accounts_dir)
        except OSError:
            return []

        accounts = []
        for account_id in candidates:
            try:
                accounts.append(self.load(account_id))
            except errors.AccountStorageError:
                logger.debug("Account loading problem", exc_info=True)
        return accounts

    def load(self, account_id):
        account_dir_path = self._account_dir_path(account_id)
        if not os.path.isdir(account_dir_path):
            raise errors.AccountNotFound(
                "Account at %s does not exist" % account_dir_path)

        try:
            with open(self._regr_path(account_dir_path)) as regr_file:
                regr = messages.RegistrationResource.json_loads(regr_file.read())
            with open(self._key_path(account_dir_path)) as key_file:
                key = jose.JWK.json_loads(key_file.read())
            with open(self._metadata_path(account_dir_path)) as metadata_file:
                meta = Account.Meta.json_loads(metadata_file.read())
        except IOError as error:
            raise errors.AccountStorageError(error)

        acc = Account(regr, key, meta)
        if acc.id != account_id:
            raise errors.AccountStorageError(
                "Account ids mismatch (expected: {0}, found: {1}".format(
                    account_id, acc.id))
        return acc

    def save(self, account):
        self._save(account, regr_only=False)

    def save_regr(self, account):
        """Save the registration resource.

        :param Account account: account whose regr should be saved

        """
        self._save(account, regr_only=True)

    def delete(self, account_id):
        """Delete registration info from disk

        :param account_id: id of account which should be deleted

        """
        account_dir_path = self._account_dir_path(account_id)
        if not os.path.isdir(account_dir_path):
            raise errors.AccountNotFound(
                "Account at %s does not exist" % account_dir_path)
        shutil.rmtree(account_dir_path)

    def _save(self, account, regr_only):
        account_dir_path = self._account_dir_path(account.id)
        util.make_or_verify_dir(account_dir_path, 0o700, os.geteuid(),
                                self.config.strict_permissions)
        try:
            with open(self._regr_path(account_dir_path), "w") as regr_file:
                regr_file.write(account.regr.json_dumps())
            if not regr_only:
                with util.safe_open(self._key_path(account_dir_path),
                                    "w", chmod=0o400) as key_file:
                    key_file.write(account.key.json_dumps())
                with open(self._metadata_path(
                        account_dir_path), "w") as metadata_file:
                    metadata_file.write(account.meta.json_dumps())
        except IOError as error:
            raise errors.AccountStorageError(error)
