"""Subscribes users to the EFF newsletter."""
import logging

import requests
import zope.component

from acme.magic_typing import Optional  # pylint: disable=unused-import

from certbot import interfaces
from certbot._internal import constants
from certbot._internal.account import Account  # pylint: disable=unused-import
from certbot._internal.account import AccountFileStorage
from certbot.interfaces import IConfig  # pylint: disable=unused-import

logger = logging.getLogger(__name__)


def prepare_subscription(config, acc):
    # type: (IConfig, Account) -> None
    """High level function to store potential EFF newsletter subscriptions.

    The user may be asked if they want to sign up for the newsletter if
    they have not given their explicit approval or refusal using --eff-mail
    or --no-eff-mail flag.

    Decision about EFF subscription will be stored in the account metadata.

    :param IConfig config: Client configuration.
    :param Account acc: Current client account.

    """
    if config.eff_email is False:
        return
    if config.eff_email is True:
        if config.email is None:
            _report_failure("you didn't provide an e-mail address")
        else:
            acc.meta = acc.meta.update(register_to_eff=config.email)
    elif config.email and _want_subscription():
        acc.meta = acc.meta.update(register_to_eff=config.email)

    if acc.meta.register_to_eff:
        storage = AccountFileStorage(config)
        storage.update_meta(acc)


def handle_subscription(config, acc):
    # type: (IConfig, Account) -> None
    """High level function to take care of EFF newsletter subscriptions.

    Once subscription is handled, it will not be handled again.

    :param IConfig config: Client configuration.
    :param Account acc: Current client account.

    """
    if config.dry_run:
        return
    if acc.meta.register_to_eff:
        subscribe(acc.meta.register_to_eff)

        acc.meta = acc.meta.update(register_to_eff=None)
        storage = AccountFileStorage(config)
        storage.update_meta(acc)


def _want_subscription():
    # type: () -> bool
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
    display = zope.component.getUtility(interfaces.IDisplay)
    return display.yesno(prompt, default=False)


def subscribe(email):
    # type: (str) -> None
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


def _check_response(response):
    # type: (requests.Response) -> None
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


def _report_failure(reason=None):
    # type: (Optional[str]) -> None
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
    reporter = zope.component.getUtility(interfaces.IReporter)
    reporter.add_message(''.join(msg), reporter.LOW_PRIORITY)
