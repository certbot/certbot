"""Subscribes users to the EFF newsletter."""
import logging

import requests
import zope.component

from certbot import interfaces
from certbot._internal import constants

logger = logging.getLogger(__name__)


def handle_subscription(config):
    """High level function to take care of EFF newsletter subscriptions.

    The user may be asked if they want to sign up for the newsletter if
    they have not already specified.

    :param .IConfig config: Client configuration.

    """
    if config.email is None:
        if config.eff_email:
            _report_failure("you didn't provide an e-mail address")
        return
    if config.eff_email is None:
        config.eff_email = _want_subscription()
    if config.eff_email:
        subscribe(config.email)


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
