"""Networking for ACME protocol."""
from acme import client
from acme import messages


class Network(client.Client):
    """ACME networking."""

    def register_from_account(self, account):
        """Register with server.

        .. todo:: this should probably not be a part of network...

        :param account: Account
        :type account: :class:`letsencrypt.account.Account`

        :returns: Updated account
        :rtype: :class:`letsencrypt.account.Account`

        """
        account.regr = self.register(messages.Registration.from_data(
            email=account.email, phone=account.phone))
        return account
