"""Simple challenges verification utilities."""
import logging

import requests


logger = logging.getLogger(__name__)


def simple_http_simple_verify(response, chall, domain):
    """Verify SimpleHTTP.

    According to the ACME specification, "the ACME server MUST ignore
    the certificate provided by the HTTPS server", so ``requests.get``
    is called with ``verify=False``.

    """
    uri = response.uri(domain)
    logger.debug("Verifying %s at %s...", chall.typ, uri)
    try:
        http_response = requests.get(uri, verify=False)
    except requests.exceptions.RequestException as error:
        logger.error("Unable to verify %s: %s", uri, error)
        return False
    logger.debug(
        'Received %s. Headers: %s', http_response, http_response.headers)

    good_token = http_response.text == chall.token
    if not good_token:
        logger.error(
            "Unable to verify %s! Expected: %r, returned: %r.",
            uri, chall.token, http_response.text)
    return response.good_path and http_response and good_token
