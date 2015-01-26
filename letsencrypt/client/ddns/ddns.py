"""generic DDNS authenticator (RFC 2136)"""

import logging
import subprocess
import StringIO

import zope.interface

from letsencrypt.client import challenge_util
from letsencrypt.client import errors
from letsencrypt.client import interfaces


class DDNS(object):
    """DDNS authenticator.

    """
    zope.interface.implements(interfaces.IAuthenticator)

    def get_chall_pref(self, unused_domain):  # pylint: disable=no-self-use
        """Return list of challenge preferences."""
        return ["dns"]

    def perform(self, chall_list):
        """Perform the configuration related challenge.

        :param list chall_list: List of challenges to be
            fulfilled by configurator.

        :returns: list of responses. All responses are returned in the same
            order as received by the perform function. A None response
            indicates the challenge was not performed.
        :rtype: list

        """
        responses = []

        for chall in chall_list:
            if isinstance(chall, challenge_util.DnsChall):
                try:
                    nsupdate("update add _acme-challenge.%s. TXT %s" % (chall.domain, chall.token))
                except:  # XXX
                    responses.append(None)
                else:
                    responses.append({"type": "dns"})
            else:
                responses.append(None)

        return responses

    def cleanup(self, chall_list):
        """Revert all challenges."""
        for chall in chall_list:
            if isinstance(chall, challenge_util.DnsChall):
                nsupdate("update del _acme-challenge.%s. TXT %s" % (chall.domain, chall.token))


def nsupdate(cmd):
    """Invoke the nsupdate commandline tool to send a single DNS update"""
    logging.debug("nsupdate %s", cmd)
    cmd = "%s\nsend\n" % cmd
    subprocess.check_call(["nsupdate", "-k", "nsupdate.key"],
                          stdin=StringIO.StringIO(cmd),
                          stdout=open("/dev/null", 'w'),
                          stderr=open("/dev/null", 'w'))
