"""Network Module."""
import json
import logging
import sys
import time

import jsonschema
import requests

from letsencrypt.client import acme
from letsencrypt.client import errors


logging.getLogger("requests").setLevel(logging.WARNING)


class Network(object):
    """Class for communicating with ACME servers.

    :ivar str server: Certificate authority server (server[:port])
    :ivar str server_url: Full URL of the CSR server

    """
    def __init__(self, server):
        self.server_url = "https://%s/acme/" % server

    def send(self, msg):
        """Send ACME message to server.

        :param dict msg: ACME message (JSON serializable).

        :returns: Server response message.
        :rtype: dict

        :raises TypeError: if `msg` is not JSON serializable
        :raises jsonschema.ValidationError: if not valid ACME message
        :raises errors.LetsEncryptClientError: in case of connection error
            or if response from server is not a valid ACME message.

        """
        json_encoded = json.dumps(msg)
        acme.acme_object_validate(json_encoded)

        try:
            response = requests.post(
                self.server_url,
                data=json_encoded,
                headers={"Content-Type": "application/json"},
                verify=True
            )
        except requests.exceptions.RequestException as error:
            raise errors.LetsEncryptClientError(
                'Sending ACME message to server has failed: %s' % error)

        try:
            acme.acme_object_validate(response.content)
        except ValueError:
            raise errors.LetsEncryptClientError(
                'Server did not send JSON serializable message')
        except jsonschema.ValidationError as error:
            raise errors.LetsEncryptClientError(
                'Response from server is not a valid ACME message')

        return response.json()

    def send_and_receive_expected(self, msg, expected):
        """Send ACME message to server and return expected message.

        :param dict msg: ACME message (JSON serializable).
        :param str expected: Name of the expected response ACME message type.

        :returns: ACME response message of expected type.
        :rtype: dict

        :raises errors.LetsEncryptClientError: An exception is thrown

        """
        response = self.send(msg)
        try:
            return self.is_expected_msg(response, expected)
        except:  # TODO: too generic exception
            raise errors.LetsEncryptClientError(
                'Expected message (%s) not received' % expected)

    def is_expected_msg(self, response, expected, delay=3, rounds=20):
        """Is response expected ACME message?

        :param dict response: ACME response message from server.
        :param str expected: Name of the expected response ACME message type.
        :param int delay: Number of seconds to delay before next round
            in case of ACME "defer" response message.
        :param int rounds: Number of resend attempts in case of ACME "defer"
            response message.

        :returns: ACME response message from server.
        :rtype: dict

        :raises LetsEncryptClientError: if server sent ACME "error" message

        """
        for _ in xrange(rounds):
            if response["type"] == expected:
                return response

            elif response["type"] == "error":
                logging.error(
                    "%s: %s - More Info: %s", response["error"],
                    response.get("message", ""), response.get("moreInfo", ""))
                raise errors.LetsEncryptClientError(response["error"])

            elif response["type"] == "defer":
                logging.info("Waiting for %d seconds...", delay)
                time.sleep(delay)
                response = self.send(acme.status_request(response["token"]))
            else:
                logging.fatal("Received unexpected message")
                logging.fatal("Expected: %s", expected)
                logging.fatal("Received: %s", response)
                sys.exit(33)

        logging.error(
            "Server has deferred past the max of %d seconds", rounds * delay)
