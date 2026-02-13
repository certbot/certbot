"""Creates ACME accounts for server."""
import datetime
import functools
import hashlib
import logging
import shutil
import socket
from typing import Any
from typing import Callable
from typing import cast
from typing import Mapping
from typing import Optional

from cryptography.hazmat.primitives import serialization
import josepy as jose
import pyrfc3339

from acme import fields as acme_fields
from acme import messages
from acme.client import ClientV2
from certbot import configuration
from certbot import errors
from certbot import interfaces
from certbot import util
from certbot._internal import constants
from certbot.compat import filesystem
from certbot.compat import os

logger = logging.getLogger(__name__)


class Account:
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
        :ivar str register_to_eff: If not None, Certbot will register the provided
                                        email during the account registration.

        .. note:: ``creation_dt`` and ``creation_host`` are useful in
            cross-machine migration scenarios.

        """
        creation_dt: datetime.datetime = acme_fields.rfc3339("creation_dt")
        creation_host: str = jose.field("creation_host")
        register_to_eff: str = jose.field("register_to_eff", omitempty=True)

    def __init__(self, regr: messages.RegistrationResource, key: jose.JWK,
                 meta: Optional['Meta'] = None) -> None:
        self.key = key
        self.regr = regr
        self.meta = self.Meta(
            # pyrfc3339 drops microseconds, make sure __eq__ is sane
            creation_dt=datetime.datetime.now(tz=datetime.timezone.utc).replace(microsecond=0),
            creation_host=socket.gethostname(),
            register_to_eff=None) if meta is None else meta

        # try MD5, else use MD5 in non-security mode (e.g. for FIPS systems / RHEL)
        try:
            hasher = hashlib.md5()
        except ValueError:
            # This cast + dictionary expansion is made to make mypy happy without the need of a
            # "type: ignore" directive that will also require to disable the check on useless
            # "type: ignore" directives when mypy is run on Python 3.9+.
            hasher = hashlib.new('md5', **cast(Mapping[str, Any], {"usedforsecurity": False}))

        hasher.update(self.key.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        )

        self.id = hasher.hexdigest()
        # Implementation note: Email? Multiple accounts can have the
        # same email address. Registration URI? Assigned by the
        # server, not guaranteed to be stable over time, nor
        # canonical URI can be generated. ACME protocol doesn't allow
        # account key (and thus its fingerprint) to be updated...

    @property
    def slug(self) -> str:
        """Short account identification string, useful for UI."""
        return "{1}@{0} ({2})".format(pyrfc3339.generate(
            self.meta.creation_dt), self.meta.creation_host, self.id[:4])

    def __repr__(self) -> str:
        return "<{0}({1}, {2}, {3})>".format(
            self.__class__.__name__, self.regr, self.id, self.meta)

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, self.__class__) and
                self.key == other.key and self.regr == other.regr and
                self.meta == other.meta)


class AccountMemoryStorage(interfaces.AccountStorage):
    """In-memory account storage."""

    def __init__(self, initial_accounts: Optional[dict[str, Account]] = None) -> None:
        self.accounts = initial_accounts if initial_accounts is not None else {}

    def find_all(self) -> list[Account]:
        return list(self.accounts.values())

    def save(self, account: Account, client: ClientV2) -> None:
        if account.id in self.accounts:
            logger.debug("Overwriting account: %s", account.id)
        self.accounts[account.id] = account

    def load(self, account_id: str) -> Account:
        try:
            return self.accounts[account_id]
        except KeyError:
            raise errors.AccountNotFound(account_id)


class AccountFileStorage(interfaces.AccountStorage):
    """Accounts file storage.

    :ivar certbot.configuration.NamespaceConfig config: Client configuration

    """
    def __init__(self, config: configuration.NamespaceConfig) -> None:
        self.config = config
        util.make_or_verify_dir(config.accounts_dir, 0o700, self.config.strict_permissions)

    def _account_dir_path(self, account_id: str) -> str:
        return self._account_dir_path_for_server_path(account_id, self.config.server_path)

    def _account_dir_path_for_server_path(self, account_id: str, server_path: str) -> str:
        accounts_dir = self.config.accounts_dir_for_server_path(server_path)
        return os.path.join(accounts_dir, account_id)

    @classmethod
    def _regr_path(cls, account_dir_path: str) -> str:
        return os.path.join(account_dir_path, "regr.json")

    @classmethod
    def _key_path(cls, account_dir_path: str) -> str:
        return os.path.join(account_dir_path, "private_key.json")

    @classmethod
    def _metadata_path(cls, account_dir_path: str) -> str:
        return os.path.join(account_dir_path, "meta.json")

    def _find_all_for_server_path(self, server_path: str) -> list[Account]:
        accounts_dir = self.config.accounts_dir_for_server_path(server_path)
        try:
            candidates = os.listdir(accounts_dir)
        except OSError:
            return []

        accounts = []
        for account_id in candidates:
            try:
                accounts.append(self._load_for_server_path(account_id, server_path))
            except errors.AccountStorageError:
                logger.debug("Account loading problem", exc_info=True)

        if not accounts and server_path in constants.LE_REUSE_SERVERS:
            # find all for the next link down
            prev_server_path = constants.LE_REUSE_SERVERS[server_path]
            prev_accounts = self._find_all_for_server_path(prev_server_path)
            # if we found something, link to that
            if prev_accounts:
                try:
                    self._symlink_to_accounts_dir(prev_server_path, server_path)
                except OSError:
                    return []
            accounts = prev_accounts
        return accounts

    def find_all(self) -> list[Account]:
        return self._find_all_for_server_path(self.config.server_path)

    def _symlink_to_account_dir(self, prev_server_path: str, server_path: str,
                                account_id: str) -> None:
        prev_account_dir = self._account_dir_path_for_server_path(account_id, prev_server_path)
        new_account_dir = self._account_dir_path_for_server_path(account_id, server_path)
        os.symlink(prev_account_dir, new_account_dir)

    def _symlink_to_accounts_dir(self, prev_server_path: str, server_path: str) -> None:
        accounts_dir = self.config.accounts_dir_for_server_path(server_path)
        if os.path.islink(accounts_dir):
            os.unlink(accounts_dir)
        else:
            os.rmdir(accounts_dir)
        prev_account_dir = self.config.accounts_dir_for_server_path(prev_server_path)
        os.symlink(prev_account_dir, accounts_dir)

    def _load_for_server_path(self, account_id: str, server_path: str) -> Account:
        account_dir_path = self._account_dir_path_for_server_path(account_id, server_path)
        if not os.path.isdir(account_dir_path): # isdir is also true for symlinks
            if server_path in constants.LE_REUSE_SERVERS:
                prev_server_path = constants.LE_REUSE_SERVERS[server_path]
                prev_loaded_account = self._load_for_server_path(account_id, prev_server_path)
                # we didn't error so we found something, so create a symlink to that
                accounts_dir = self.config.accounts_dir_for_server_path(server_path)
                # If accounts_dir isn't empty, make an account specific symlink
                if os.listdir(accounts_dir):
                    self._symlink_to_account_dir(prev_server_path, server_path, account_id)
                else:
                    self._symlink_to_accounts_dir(prev_server_path, server_path)
                return prev_loaded_account
            raise errors.AccountNotFound(f"Account at {account_dir_path} does not exist")

        try:
            with open(self._regr_path(account_dir_path)) as regr_file:
                regr = messages.RegistrationResource.json_loads(regr_file.read())
            with open(self._key_path(account_dir_path)) as key_file:
                key = jose.JWK.json_loads(key_file.read())
            with open(self._metadata_path(account_dir_path)) as metadata_file:
                meta = Account.Meta.json_loads(metadata_file.read())
        except OSError as error:
            raise errors.AccountStorageError(error)

        return Account(regr, key, meta)

    def load(self, account_id: str) -> Account:
        return self._load_for_server_path(account_id, self.config.server_path)

    def save(self, account: Account, client: ClientV2) -> None:
        """Create a new account.

        :param Account account: account to create
        :param ClientV2 client: ACME client associated to the account

        """
        try:
            dir_path = self._prepare(account)
            self._create(account, dir_path)
            self._update_meta(account, dir_path)
            self._update_regr(account, dir_path)
        except OSError as error:
            raise errors.AccountStorageError(error)

    def update_regr(self, account: Account) -> None:
        """Update the registration resource.

        :param Account account: account to update

        """
        try:
            dir_path = self._prepare(account)
            self._update_regr(account, dir_path)
        except OSError as error:
            raise errors.AccountStorageError(error)

    def update_meta(self, account: Account) -> None:
        """Update the meta resource.

        :param Account account: account to update

        """
        try:
            dir_path = self._prepare(account)
            self._update_meta(account, dir_path)
        except OSError as error:
            raise errors.AccountStorageError(error)

    def delete(self, account_id: str) -> None:
        """Delete registration info from disk

        :param account_id: id of account which should be deleted

        """
        account_dir_path = self._account_dir_path(account_id)
        if not os.path.isdir(account_dir_path):
            raise errors.AccountNotFound(f"Account at {account_dir_path} does not exist")
        # Step 1: Delete account specific links and the directory
        self._delete_account_dir_for_server_path(account_id, self.config.server_path)

        # Step 2: Remove any accounts links and directories that are now empty
        if not os.listdir(self.config.accounts_dir):
            self._delete_accounts_dir_for_server_path(self.config.server_path)

    def _delete_account_dir_for_server_path(self, account_id: str, server_path: str) -> None:
        link_func = functools.partial(self._account_dir_path_for_server_path, account_id)
        nonsymlinked_dir = self._delete_links_and_find_target_dir(server_path, link_func)
        shutil.rmtree(nonsymlinked_dir)

    def _delete_accounts_dir_for_server_path(self, server_path: str) -> None:
        link_func = self.config.accounts_dir_for_server_path
        nonsymlinked_dir = self._delete_links_and_find_target_dir(server_path, link_func)
        os.rmdir(nonsymlinked_dir)

    def _delete_links_and_find_target_dir(self, server_path: str,
                                          link_func: Callable[[str], str]) -> str:
        """Delete symlinks and return the nonsymlinked directory path.

        :param str server_path: file path based on server
        :param callable link_func: callable that returns possible links
            given a server_path

        :returns: the final, non-symlinked target
        :rtype: str

        """
        dir_path = link_func(server_path)

        # does an appropriate directory link to me? if so, make sure that's gone
        reused_servers = {}
        for k, v in constants.LE_REUSE_SERVERS.items():
            reused_servers[v] = k

        # is there a next one up?
        possible_next_link = True
        while possible_next_link:
            possible_next_link = False
            if server_path in reused_servers:
                next_server_path = reused_servers[server_path]
                next_dir_path = link_func(next_server_path)
                if os.path.islink(next_dir_path) and filesystem.readlink(next_dir_path) == dir_path:
                    possible_next_link = True
                    server_path = next_server_path
                    dir_path = next_dir_path

        # if there's not a next one up to delete, then delete me
        # and whatever I link to
        while os.path.islink(dir_path):
            target = filesystem.readlink(dir_path)
            os.unlink(dir_path)
            dir_path = target

        return dir_path

    def _prepare(self, account: Account) -> str:
        account_dir_path = self._account_dir_path(account.id)
        util.make_or_verify_dir(account_dir_path, 0o700, self.config.strict_permissions)
        return account_dir_path

    def _create(self, account: Account, dir_path: str) -> None:
        with util.safe_open(self._key_path(dir_path), "w", chmod=0o400) as key_file:
            key_file.write(account.key.json_dumps())

    def _update_regr(self, account: Account, dir_path: str) -> None:
        with open(self._regr_path(dir_path), "w") as regr_file:
            regr = messages.RegistrationResource(
                body={},
                uri=account.regr.uri)
            regr_file.write(regr.json_dumps())

    def _update_meta(self, account: Account, dir_path: str) -> None:
        with open(self._metadata_path(dir_path), "w") as metadata_file:
            metadata_file.write(account.meta.json_dumps())
