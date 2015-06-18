"""Networking for ACME protocol."""
from acme import client


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
        details = (
            "mailto:" + account.email if account.email is not None else None,
            "tel:" + account.phone if account.phone is not None else None,
        )
        account.regr = self.register(contact=tuple(
            det for det in details if det is not None))
        return account
