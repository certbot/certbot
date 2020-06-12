"""Subscribes users to the EFF newsletter."""
import logging

import requests
import zope.component
from acme.client import Client, BackwardsCompatibleClientV2, ClientBase

from certbot import interfaces
from certbot._internal import constants
from certbot._internal.account import Account, AccountFileStorage
from certbot.interfaces import IConfig

logger = logging.getLogger(__name__)


def prepare_subscription(config, acc, acme):
    # type: (IConfig, Account, ClientBase) -> None
    if config.eff_email is False:
        return
    if config.eff_email is True:
        if config.email is None:
            _report_failure("you didn't provide an e-mail address")
        else:
            acc.meta = acc.meta.update(will_register_to_eff=config.email)
    elif config.email:
        # Case of no explicit approval or refusal to subscribe to EFF
        acc.meta = acc.meta.update(propose_eff_registration=config.email)

    if acc.meta.will_register_to_eff or acc.meta.propose_eff_registration:
        storage = AccountFileStorage(config)
        storage.update(acc, acme)


def handle_subscription(config, acc, acme):
    # type: (IConfig, Account, ClientBase) -> None
    email_to_subscribe = None

    if acc.meta.will_register_to_eff:
        email_to_subscribe = acc.meta.will_register_to_eff
    elif acc.meta.propose_eff_registration and _want_subscription():
        email_to_subscribe = acc.meta.propose_eff_registration

    if email_to_subscribe:
        subscribe(email_to_subscribe)

    if acc.meta.will_register_to_eff or acc.meta.propose_eff_registration:
        acc.meta = acc.meta.update(will_register_to_eff=None, propose_eff_registration=None)
        storage = AccountFileStorage(config)
        storage.update(acc, acme)


def _want_subscription():
    """Does the user want to be subscribed to the EFF newsletter?

    :returns: True if we should subscribe the user, otherwise, False
    :rtype: bool

    """
    prompt = (
        'Would you be willing to share your email address with the '
        "Electronic Frontier Foundation, a founding partner of the Let's "
        'Encrypt project and the non-profit organization that develops '
        "Certbot? We'd like to send you email about our work encrypting "
        "the web, EFF news, campaigns, and ways to support digital freedom. ")
    display = zope.component.getUtility(interfaces.IDisplay)
    return display.yesno(prompt, default=False)


def subscribe(email):
    """Subscribe the user to the EFF mailing list.

    :param str email: the e-mail address to subscribe

    """
    url = constants.EFF_SUBSCRIBE_URI
    data = {'data_type': 'json',
            'email': email,
            'form_id': 'eff_supporters_library_subscribe_form'}
    logger.debug('Sending POST request to %s:\n%s', url, data)
    _check_response(requests.post(url, data=data))


def _check_response(response):
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
