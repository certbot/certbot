#!/usr/bin/env python

import web, shelve, time
import CSR
from Crypto.Hash import SHA256, HMAC
from Crypto import Random 
from chocolate_protocol_pb2 import chocolatemessage
from google.protobuf.message import DecodeError

MaximumSessionAge = 100   # seconds, to demonstrate timeout

def hmac(k, m):
    return HMAC.new(k, m, SHA256).hexdigest()

urls = (
     '.*', 'index'
)

class sessionstore(object):
    def __init__(self, f="/tmp/chocolate-sessions.shelve"):
        self.f = shelve.open(f, "c")

    def exists(self, session):
        return session in self.f

    def live(self, session):
        return session in self.f and self.f[session]["live"]

    def create(self, session, timestamp):
        if session not in self.f:
            self.f[session] = {"created": timestamp, "live": True}
        else:
            raise KeyError

    def kill(self, session):
        temp = self.f[session]
        temp["live"] = False
        self.f[session] = temp

    def destroy(self, session):
        del self.f[session]

    def age(self, session):
        return int(time.time()) - self.f[session]["created"] 

    def make_request(self, session, request):
        self.f["request"] = request

    def get_request(self, session):
        return self.f["request"]

    def request_made(self, session):
        return "request" in self.f[session]

class index:
    def GET(self):
        web.header("Content-type", "text/html")
        return "Hello, world!  This server only accepts POST requests."

    def killsession(self):
        self.sessions.kill(self.session)

    def handlesession(self, m, r):
        if m.session == "":
            # New session
            r.session = SHA256.new(Random.get_random_bytes(32)).hexdigest()
            self.session = r.session.encode("UTF8")
            self.sessions.create(self.session, int(time.time()))
        elif m.session and not r.failure.IsInitialized():
            self.session = m.session.encode("UTF8")
            r.session = self.session
            if not self.sessions.exists(self.session):
                r.failure.cause = r.StaleRequest
            elif not self.sessions.live(self.session):
                r.failure.cause = r.StaleRequest
            elif self.sessions.age(self.session) > MaximumSessionAge:
                self.killsession()
                r.failure.cause = r.StaleRequest

    def handleclientfailure(self, m, r):
        if r.failure.IsInitialized(): return
        if m.failure.IsInitialized():
            # Received failure message from client!
            self.killsession()
            r.failure.cause = r.AbandonedRequest

    def handlesigningrequest(self, m, r):
        if r.failure.IsInitialized(): return
        if not m.request: return
        if self.sessions.request_made(self.session):
            self.killsession()
            r.failure.cause = r.BadRequest
            r.failure.uri = "https://ca.example.com/failures/request"
            return
        # TODO: currently only examine the first request
        # TODO: check client puzzle
        timestamp = m.request[0].timestamp
        recipient = m.request[0].recipient
        nonce = m.request[0].nonce
        csr = m.request[0].csr
        sig = m.request[0].sig
        if timestamp > time.time() or time.time() - timestamp > 100:
            self.killsession()
            r.failure.cause = r.BadRequest
            r.failure.affectedrequest = nonce
            r.failure.uri = "https://ca.example.com/failures/time"
            return
        if recipient != "ca.example.com":
            self.killsession()
            r.failure.cause = r.BadRequest
            r.failure.affectedrequest = nonce
            r.failure.uri = "https://ca.example.com/failures/recipient"
            return
        if not CSR.parse(csr):
            self.killsession()
            r.failure.cause = r.BadCSR
            r.failure.affectedrequest = nonce
            return
        # if CSR.verify(pubkey(csr), sig) != hmac("chocolate-request-ca-example.com", /%d/%s/%s/%s" % (timestamp, recipient, nonce, csr))):
        #     self.killsession()
        #     r.failure.cause = BadSignature
        #     r.failure.affectedrequest = nonce
        #     self.killsession()
        #     return
        if not CSR.goodkey(csr):
            self.killsession()
            r.failure.cause = r.UnsafeKey
            r.failure.affectedrequest = nonce
            return

    def POST(self):
        web.header("Content-type", "application/x-protobuf")
#        web.setcookie("chocolate", hmac("foo", "bar"),
#                       secure=True) # , httponly=True)
        self.sessions = sessionstore()
        m = chocolatemessage()
        r = chocolatemessage()
        r.chocolateversion = 1
        try:
            m.ParseFromString(web.data())
        except DecodeError:
            r.failure.cause = r.BadRequest
        else:
            if m.chocolateversion != 1:
                r.failure.cause = r.UnsupportedVersion
        self.handlesession(m, r)

        self.handleclientfailure(m, r)

        self.handlesigningrequest(m, r)

        # Send reply
        if m.debug:
            web.header("Content-type", "text/plain")
            return "SAW MESSAGE: %s\n" % str(r)
        else:
            return r.SerializeToString()

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
