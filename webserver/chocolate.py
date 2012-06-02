#!/usr/bin/env python

import web, redis, time
import CSR
from Crypto.Hash import SHA256, HMAC
from Crypto import Random 
from chocolate_protocol_pb2 import chocolatemessage
from google.protobuf.message import DecodeError

MaximumSessionAge = 100   # seconds, to demonstrate timeout

urls = (
     '.*', 'index'
)

def sha256(m):
    return SHA256.new(m).hexdigest()

def hmac(k, m):
    return HMAC.new(k, m, SHA256).hexdigest()

def safe(what, s):
    """Is string s within the allowed-character policy for this field?"""
    if not isinstance(s, basestring):
        return False
    base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    csr_ok = base64 + " =-"
    if what == "nonce":
        return s.isalnum()
    elif what == "recipient":
        return all(c.isalnum() or c in "-." for c in s)
    elif what == "csr":
       return all(all(c in csr_ok for c in line) for line in s.split("\n"))
       # Note that this implies CSRs must have LF for end-of-line, not CRLF
    else:
       return False

sessions = redis.Redis()

class session(object):
    def __init__(self, sessionid):
        self.id = sessionid

    def exists(self):
        return self.id in sessions

    def live(self):
        return self.id in sessions and sessions.hget(self.id, "live") == "True"

    def create(self, timestamp=int(time.time())):
        if not self.exists():
            sessions.hset(self.id, "created", timestamp)
            sessions.hset(self.id, "live", True)
        else:
            raise KeyError

    def kill(self):
        sessions.hset(self.id, "live", False)

    def destroy(self):
        sessions.delete(self.id)

    def age(self):
        return int(time.time()) - int(sessions.hget(self.id, "created"))

    def request_made(self):
        """Has there already been any signing request made in this session?"""
        return sessions.llen(self.id + ":requests") > 0

    def add_request(self, nonce, cn, csr):
        if sessions.hget(self.id + ":req:" + nonce):
            # duplicate nonce
            return False
        # TODO: is it safe to use the client-supplied nonce for naming the request?
        sessions.hset(self.id + ":req:" + nonce, "cn", cn)
        sessions.hset(self.id + ":req:" + nonce, "csr", csr)
        sessions.rpush(self.id + ":requests", nonce)

class index(object):
    def GET(self):
        web.header("Content-type", "text/html")
        return "Hello, world!  This server only accepts POST requests."

    def handlesession(self, m, r):
        if m.session == "":
            # New session
            r.session = SHA256.new(Random.get_random_bytes(32)).hexdigest()
            self.session = session(r.session)
            if not self.session.exists():
                self.session.create()
            else:
                raise ValueError, "new random session already existed!"
        elif m.session and not r.failure.IsInitialized():
            self.session = session(m.session)
            r.session = m.session
            if not (self.session.exists() and self.session.live()):
                # Don't need to, or can't, kill nonexistent/already dead session
                r.failure.cause = r.StaleRequest
            elif self.session.age() > MaximumSessionAge:
                self.die(r, r.StaleRequest)

    def die(self, r, reason, nonce=None, uri=None):
        self.session.kill()
        r.failure.cause = reason
        if nonce: r.failure.affectedrequest = nonce
        if uri: r.failure.URI = uri

    def handleclientfailure(self, m, r):
        if r.failure.IsInitialized(): return
        if m.failure.IsInitialized():
            # Received failure message from client!
            self.die(r, r.AbandonedRequest)

    def handlesigningrequest(self, m, r):
        if r.failure.IsInitialized(): return
        if not m.request: return
        if self.session.request_made():
            # Can't make new signing requests if there have already been requests in
            # this session.  (All signing requests should occur together at the
            # beginning.)
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/priorrequest")
            return
        # TODO: currently only examine the first request, but this should be a loop.
        # TODO: check client puzzle
        timestamp = m.request[0].timestamp
        recipient = m.request[0].recipient
        nonce = m.request[0].nonce
        csr = m.request[0].csr
        sig = m.request[0].sig
        if not all([safe("recipient", recipient), safe("nonce", nonce), safe("csr", csr)]):
            self.die(r, r.BadRequest, nonce, "https://ca.example.com/failures/illegalcharacter")
            return
        if timestamp > time.time() or time.time() - timestamp > 100:
            self.die(r, r.BadRequest, nonce, "https://ca.example.com/failures/time")
            return
        if recipient != "ca.example.com":
            self.die(r, r.BadRequest, nonce, "https://ca.example.com/failures/recipient")
            return
        if not CSR.parse(csr):
            self.die(r, r.BadCSR, nonce)
            return
        if CSR.verify(CSR.pubkey(csr), sig) != sha256("(%d) (%s) (%s) (%s)" % (timestamp, recipient, nonce, csr)):
            self.die(r, r.BadSignature, nonce)
            return
        if not CSR.csr_goodkey(csr):
            self.die(r, r.UnsafeKey, nonce)
            return
        if not CSR.can_sign(CSR.cn(csr)):
            self.die(r, r.CannotIssueThatName, nonce)
            return
        # TODO: check goodness of subjectAltName fields!
        if not self.session.add_request(nonce, CSR.cn(csr), csr):
            self.die(r, r.BadRequest, nonce, "https://ca.example.com/failures/duplicatenonce")
            return
        r.proceed.timestamp = int(time.time())
        r.proceed.polldelay = 10

    def POST(self):
        web.header("Content-type", "application/x-protobuf")
#        web.setcookie("chocolate", hmac("foo", "bar"),
#                       secure=True) # , httponly=True)
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
