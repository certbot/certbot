import json
import os
import sys

import configobj
import zope.component

from letsencrypt.acme import messages2

from letsencrypt.client import crypto_util
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util

from letsencrypt.client.display import ops as display_ops


class Account(object):
    """ACME protocol registration.

    :ivar config: Client configuration object
    :type config: :class:`~letsencrypt.client.interfaces.IConfig`
    :ivar key: Account/Authorized Key
    :type key: :class:`~letsencrypt.client.le_util.Key`

    :ivar str email: Client's email address
    :ivar str phone: Client's phone number

    :ivar bool save: Whether or not to save the account information

    :ivar regr: Registration Resource
    :type regr: :class:`~letsencrypt.acme.messages2.RegistrationResource`

    """
    def __init__(self, config, key, email=None, phone=None, regr=None):
        self.key = key
        self.config = config
        self.email = email
        self.phone = phone

        self.regr = regr

    def save(self):
        # account_dir = le_util.make_or_verify_dir(
        #     os.path.join(self.config.config_dir, "accounts"))
        # account_key_dir = le_util.make_or_verify_dir(
        #     os.path.join(account_dir, "keys"), 0o700)

        acc_config = configobj.ConfigObj()
        # acc_config.filename = os.path.join(
        #     account_dir, self._get_config_filename())
        acc_config.filename = sys.stdout

        acc_config.initial_comment = [
            "Account information for %s under %s" % (
                self._get_config_filename(self.email), self.config.server)]
        acc_config["key"] = self.key.path
        acc_config["phone"] = self.phone

        regr_json = self.regr.to_json()
        regr_dict = json.loads(regr_json)

        acc_config["regr"] = regr_dict
        acc_config.write()

    @classmethod
    def _get_config_filename(self, email):
        return email if email is not None else "default"

    @classmethod
    def from_existing_account(cls, config, email=None):
        accounts_dir = os.path.join(
            config.config_dir, "accounts", config.server)
        config_fp = os.path.join(accounts_dir, cls._get_config_filename(email))
        return cls._from_config_fp(config, config_fp)

    @classmethod
    def _from_config_fp(cls, config, config_fp):
        try:
            acc_config = configobj.ConfigObj(
                infile=config_fp, file_error=True, create_empty=False)
        except IOError:
            raise errors.LetsEncryptClientError(
                "Account for %s does not exist" % os.path.basename(config_fp))
        json_regr = json.dumps(acc_config["regr"])
        return cls(config, acc_config["key"], acc_config["email"],
                   acc_config["phone"],
                   messages2.RegistrationResource.from_json(json_regr))

    @classmethod
    def choose_account(cls, config):
        """Choose one of the available accounts."""
        accounts = []
        accounts_dir = os.path.join(config.config_dir, "accounts")
        filenames = os.listdir(accounts_dir)
        for name in filenames:
            # Not some directory ie. keys
            config_fp = os.path.join(accounts_dir, name)
            if os.path.isfile(config_fp):
                accounts.append(cls._from_config_fp(config, config_fp))

        if len(accounts) == 1:
            return accounts[0]
        elif len(accounts) > 1:
            return display_ops.choose_account(accounts)
        else:
            return None

    @classmethod
    def from_prompts(cls, config):
        email = zope.component.getUtility(interfaces.IDisplay).input(
            "Enter email address")
        key_dir = os.path.join(config.config_dir, "accounts", config.server, "keys")
        key = crypto_util.init_save_key(2048, config.accounts_dir, email)
        return cls(config, email, key)