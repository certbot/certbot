"""Subscribes users to the EFF newsletter."""
import logging
from typing import cast
from typing import Optional

import requests

from certbot import configuration
from certbot._internal import constants
from certbot._internal.account import Account
from certbot._internal.account import AccountFileStorage
from certbot.display import util as display_util

logger = logging.getLogger(__name__)


def prepare_subscription(config: configuration.NamespaceConfig, acc: Account) -> None:
    """High level function to store potential EFF newsletter subscriptions.

    The user may be asked if they want to sign up for the newsletter if
    they have not given their explicit approval or refusal using --eff-mail
    or --no-eff-mail flag.

    Decision about EFF subscription will be stored in the account metadata.

    :param configuration.NamespaceConfig config: Client configuration.
    :param Account acc: Current client account.

    """
    if config.eff_email is False:
        return
    if config.eff_email is True:
        if config.email is None:
            _report_failure("you didn't provide an e-mail address")
        else:
            # TODO: Remove cast when https://github.com/certbot/certbot/pull/9073 is merged.
            acc.meta = cast(Account.Meta, acc.meta.update(register_to_eff=config.email))
    elif config.email and _want_subscription():
        # TODO: Remove cast when https://github.com/certbot/certbot/pull/9073 is merged.
        acc.meta = cast(Account.Meta, acc.meta.update(register_to_eff=config.email))

    if acc.meta.register_to_eff:
        storage = AccountFileStorage(config)
        storage.update_meta(acc)


# TODO this needs to be changed as well to support accounts with elliptic curves
def handle_subscription(config: configuration.NamespaceConfig, acc: Optional[Account]) -> None:
    """High level function to take care of EFF newsletter subscriptions.

    Once subscription is handled, it will not be handled again.

    :param configuration.NamespaceConfig config: Client configuration.
    :param Account acc: Current client account.

    """
    if config.dry_run or not acc:
        return
    if acc.meta.register_to_eff:
        # TODO: Remove cast when https://github.com/certbot/certbot/pull/9073 is merged.
        subscribe(cast(str, acc.meta.register_to_eff))

        # TODO: Remove cast when https://github.com/certbot/certbot/pull/9073 is merged.
        acc.meta = cast(Account.Meta, acc.meta.update(register_to_eff=None))
        storage = AccountFileStorage(config)
        storage.update_meta(acc)


def _want_subscription() -> bool:
    """Does the user want to be subscribed to the EFF newsletter?

    :returns: True if we should subscribe the user, otherwise, False
    :rtype: bool

    """
    prompt = (
        'Would you be willing, once your first certificate is successfully issued, '
        'to share your email address with the Electronic Frontier Foundation, a '
        "founding partner of the Let's Encrypt project and the non-profit organization "
        "that develops Certbot? We'd like to send you email about our work encrypting "
        "the web, EFF news, campaigns, and ways to support digital freedom. ")
    return display_util.yesno(prompt, default=False)


def subscribe(email: str) -> None:
    """Subscribe the user to the EFF mailing list.

    :param str email: the e-mail address to subscribe

    """
    url = constants.EFF_SUBSCRIBE_URI
    data = {'data_type': 'json',
            'email': email,
            'form_id': 'eff_supporters_library_subscribe_form'}
    logger.info('Subscribe to the EFF mailing list (email: %s).', email)
    logger.debug('Sending POST request to %s:\n%s', url, data)
    _check_response(requests.post(url, data=data))


def _check_response(response: requests.Response) -> None:
    """Check for errors in the server's response.

    If an error occurred, it will be reported to the user.

    :param requests.Response response: the server's response to the
        subscription request

    """
    logger.debug('Received response:\n%s', response.content)
    try:
        response.raise_for_status()
        if not response.json()['status']:
            _report_failure('your e-mail address appears to be invalid')
    except requests.exceptions.HTTPError:
        _report_failure()
    except (ValueError, KeyError):
        _report_failure('there was a problem with the server response')


def _report_failure(reason: Optional[str] = None) -> None:
    """Notify the user of failing to sign them up for the newsletter.

    :param reason: a phrase describing what the problem was
        beginning with a lowercase letter and no closing punctuation
    :type reason: `str` or `None`

    """
    msg = ['We were unable to subscribe you the EFF mailing list']
    if reason is not None:
        msg.append(' because ')
        msg.append(reason)
    msg.append('. You can try again later by visiting https://act.eff.org.')
    display_util.notify(''.join(msg))
