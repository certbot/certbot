"""Standalone DNS Authenticator."""
import logging

import copy

from dnslib import RR
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)
dnsLogger = DNSLogger("truncated,error",False)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """Standalone DNS Authenticator

    This Authenticator uses a standalone DNS server to fulfill a dns-01 challenge.

    Note that this plugin is not thread-safe.
    """

    description = ('Obtain certificates using an integrated DNS server')

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.resolver = None
        self.udp_server = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=0)
        add('address', help='IP address to bind to.', default='0.0.0.0')

    def _setup_credentials(self):
        return

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin uses a standalone DNS server to respond to a dns-01 challenge.'

    def _perform(self, domain, validation_name, validation):
        self.resolver = _AcmeResolver(validation)

        try:
            self.udp_server = DNSServer(self.resolver, port=53, address=self.conf('address'),
                                        logger=dnsLogger)
            self.udp_server.start_thread()
        except Exception as e:
            raise errors.PluginError('Error starting DNS server: {0}'.format(e))

    def _cleanup(self, domain, validation_name, validation):
        if self.udp_server:
            self.udp_server.stop()


class _AcmeResolver(BaseResolver):
    def __init__(self,token):
        self.arrs = RR.fromZone(". 60 A 127.0.0.1") # for dig
        self.trrs = RR.fromZone(". 60 TXT %s" % token)
        self.isDone = False

    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname

        if request.q.qtype == 16:
            resp = self.trrs
            self.isDone = True
        else:
            resp = self.arrs

        if request.q.qtype == 1 or request.q.qtype == 16:
            for rr in resp:
                a = copy.copy(rr)
                a.rname = qname
                reply.add_answer(a)

        return reply
    def isDone():
        return self.isDone
