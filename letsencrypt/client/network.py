"""Network Module."""
import logging
import sys
import time

import requests

from letsencrypt.acme import messages

from letsencrypt.client import errors


logging.getLogger("requests").setLevel(logging.WARNING)


class Network(object):
    """Class for communicating with ACME servers.

    :ivar str server_url: Full URL of the ACME service

    """
    def __init__(self, server):
        """Initialize Network instance.

        :param str server: ACME (CA) server[:port]

        """
        self.server_url = "https://%s/acme/" % server

    def send(self, msg):
        """Send ACME message to server.

        :param msg: ACME message.
        :type msg: :class:`letsencrypt.acme.messages.Message`

        :returns: Server response message.
        :rtype: :class:`letsencrypt.acme.messages.Message`

        :raises TypeError: if `msg` is not JSON serializable
        :raises jsonschema.ValidationError: if not valid ACME message
        :raises errors.Error: in case of connection error
            or if response from server is not a valid ACME message.

        """
        try:
            response = requests.post(
                self.server_url,
                data=msg.json_dumps(),
                headers={"Content-Type": "application/json"},
                verify=True
            )
        except requests.exceptions.RequestException as error:
            raise errors.Error(
                'Sending ACME message to server has failed: %s' % error)

        return messages.Message.from_json(response.json(), validate=True)

    def send_and_receive_expected(self, msg, expected):
        """Send ACME message to server and return expected message.

        :param msg: ACME message.
        :type msg: :class:`letsencrypt.acme.Message`

        :returns: ACME response message of expected type.
        :rtype: :class:`letsencrypt.acme.messages.Message`

        :raises errors.Error: An exception is thrown

        """
        response = self.send(msg)
        return self.is_expected_msg(response, expected)


    def is_expected_msg(self, response, expected, delay=3, rounds=20):
        """Is response expected ACME message?

        :param response: ACME response message from server.
        :type response: :class:`letsencrypt.acme.messages.Message`

        :param expected: Expected response type.
        :type expected: subclass of :class:`letsencrypt.acme.messages.Message`

        :param int delay: Number of seconds to delay before next round
            in case of ACME "defer" response message.
        :param int rounds: Number of resend attempts in case of ACME "defer"
            response message.

        :returns: ACME response message from server.
        :rtype: :class:`letsencrypt.acme.messages.Message`

        :raises ClientError: if server sent ACME "error" message

        """
        for _ in xrange(rounds):
            if isinstance(response, expected):
                return response
            elif isinstance(response, messages.Error):
                logging.error("%s", response)
                raise errors.Error(response.error)
            elif isinstance(response, messages.Defer):
                logging.info("Waiting for %d seconds...", delay)
                time.sleep(delay)
                response = self.send(
                    messages.StatusRequest(token=response.token))
            else:
                logging.fatal("Received unexpected message")
                logging.fatal("Expected: %s", expected)
                logging.fatal("Received: %s", response)
                sys.exit(33)

        logging.error(
            "Server has deferred past the max of %d seconds", rounds * delay)
