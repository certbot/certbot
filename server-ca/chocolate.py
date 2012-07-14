#!/usr/bin/env python

import web, redis, time
import CSR
import hashlib
import hmac
from CSR import M2Crypto
from Crypto import Random
from chocolate_protocol_pb2 import chocolatemessage
from google.protobuf.message import DecodeError

MaximumSessionAge = 100   # seconds, to demonstrate session timeout
MaximumChallengeAge = 600 # to demonstrate challenge timeout

try:
    chocolate_server_name = open("SERVERNAME").read().rstrip()
except IOError:
    raise IOError, "Please create a SERVERNAME file containing the server name."

urls = (
     '.*', 'session'
)

def sha256(m):
    return hashlib.sha256(m).hexdigest()

def hmac(k, m):
    return hmac.new(k, m, hashlib.sha256).hexdigest()

def random():
    """Return 64 hex digits representing a new 32-byte random number."""
    return sha256(Random.get_random_bytes(32))

def safe(what, s):
    """Is string s within the allowed-character policy for this field?"""
    if not isinstance(s, basestring):
        return False
    if len(s) == 0:
        # No validated string should be empty.
        return False
    base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    csr_ok = base64 + " =-"
#    if what == "nonce":
#        return s.isalnum()
    if what == "recipient" or what == "hostname":
        return all(c.isalnum() or c in "-." for c in s)
    elif what == "csr":
       return all(all(c in csr_ok for c in line) for line in s.split("\n"))
       # Note that this implies CSRs must have LF for end-of-line, not CRLF
    elif what == "session":
       return len(s) == 64 and all(c in "0123456789abcdef" for c in s)
    else:
       return False

sessions = redis.Redis()

class session(object):
    def __init__(self):
        self.id = None

    def exists(self):
        return self.id in sessions

    def live(self):
        return self.id in sessions and sessions.hget(self.id, "live") == "True"

    def state(self):
        # Should be:
        # * None for a session where the signing request has not
        #   yet been received;
        # * "makechallenge" where the CA is still coming up with challenges,
        # * "testchallenge" where the challenges have been issued,
        # * "issue" where the CA is in the process of issuing the cert,
        # * "done" where the cert has been issued.
        #
        # Note that this is independent of "live", which specifies whether
        # further actions involving this session are permitted.  When
        # sessions die, they currently keep their last state, but the
        # client can't cause their state to advance further.  For example,
        # if a session times out while waiting for the client to complete
        # a challenge, we have state="testchallenge", but live="False".
        return sessions.hget(self.id, "state")

    def create(self, timestamp=None):
        if timestamp is None: timestamp = int(time.time())
        if not self.exists():
            sessions.hset(self.id, "created", timestamp)
            sessions.hset(self.id, "live", True)
            sessions.lpush("active-requests", self.id)
        else:
            raise KeyError

    def kill(self):
        # It is now possible to get here via die() even if there is no session
        # ID, because we can die() on the initial request before a session ID
        # has been allocated!
        if self.id:
            sessions.hset(self.id, "live", False)
            sessions.lrem("active-requests", self.id)

    def destroy(self):
        sessions.lrem("active-requests", self.id)
        sessions.delete(self.id)

    def age(self):
        return int(time.time()) - int(sessions.hget(self.id, "created"))

    def request_made(self):
        """Has there already been a signing request made in this session?"""
        return sessions.hget(self.id, "state") is not None

    def pubkey(self):
        """Return the PEM-formatted subject public key from the CSR."""
        return CSR.pubkey(sessions.hget(self.id, "csr"))

    def cert(self):
        """Return the issued certificate."""
        return sessions.hget(self.id, "cert")

    def add_request(self, csr, names):
        sessions.hset(self.id, "csr", csr)
        for name in names: sessions.rpush(self.id + ":names", name)
        sessions.hset(self.id, "state", "makechallenge")
        sessions.lpush("pending-makechallenge", self.id)
        return True

    def challenges(self):
        n = int(sessions.hget(self.id, "challenges"))
        for i in xrange(n):
            yield sessions.hgetall("%s:%d" % (self.id, i))

    def send_cert(self, m, r):
        """Initialize response to return issued cert to client."""
        if self.cert():
            r.success.certificate = self.cert()
        else:
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/internalerror")
        return

    def handlesession(self, m, r):
        if r.failure.IsInitialized(): return
        # Note that m.challenge and m.completedchallenge present
        # as lists, which are True if they are nonempty.  By
        # contrast, m.proceed, m.success, m.request, and m.failure
        # are always True but have an .IsInitialized() property
        # indicating whether they are actually present in m as
        # messages from the client.
        #
        # Check for some ways in which the message from the client
        # can be inappropriate.
        if m.challenge or m.proceed.IsInitialized() or m.success.IsInitialized():
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/invalidfromclient")
            return
        distinct_messages = 0
        if m.request.IsInitialized(): distinct_messages += 1
        if m.failure.IsInitialized(): distinct_messages += 1
        if m.completedchallenge: distinct_messages += 1
        if distinct_messages > 1:
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/mixedmessages")
            return
        # The rule that a new session must contain a request is enforced
        # by handlenewsession.  The rule that an existing session must
        # not contain a request is enforced by handleexistingsession.
        # TODO: check that there are no bad cases that slip through.
        if m.session == "":
            # New session
            r.session = random()
            self.id = r.session
            if not self.exists():
                self.create()
                self.handlenewsession(m, r)
            else:
                raise ValueError, "new random session already existed!"
        elif m.session and not r.failure.IsInitialized():
            r.session = ""
            if not safe("session", m.session):
                # Note that self.id is still uninitialized here.
                self.die(r, r.BadRequest, uri="https://ca.example.com/failures/illegalsession")
                return
            self.id = m.session
            r.session = m.session
            if not (self.exists() and self.live()):
                # Don't need to, or can't, kill nonexistent/already dead session
                r.failure.cause = r.StaleRequest
            elif self.age() > MaximumSessionAge:
                # TODO: Sessions in state "done" should probably not be killed by timeout
                # because they have already resulted in issuance of a cert and no further
                # issuance can occur.  At least, their timeout should probably be extended
                # to 48 hours or something.  Currently, a session can die by timeout in
                # any state.  In general, the allowed age of a session that's further
                # along in the process should be longer.  This is particular true when
                # we're testing challenges because the amount of time required for this
                # may not be under the client's control at all.
                self.die(r, r.StaleRequest)
            else:
                self.handleexistingsession(m, r)

    def handlenewsession(self, m, r):
        if r.failure.IsInitialized(): return
        if not m.request.IsInitialized():
            # It is mandatory to make a signing request at the outset of a session.
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/missingrequest")
            return
        if self.request_made():
            # Can't make new signing requests if there have already been requests in
            # this session.  (All signing requests should occur together at the
            # beginning.)
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/priorrequest")
            return
        # Process the request.
        # TODO: check client puzzle before processing request
        timestamp = m.request.timestamp
        recipient = m.request.recipient
        csr = m.request.csr
        sig = m.request.sig
        if not all([safe("recipient", recipient), safe("csr", csr)]):
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/illegalcharacter")
            return
        if timestamp - time.time() > 5:
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/future")
            return
        if time.time() - timestamp > 100:
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/past")
            return
        if recipient != chocolate_server_name:
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/recipient")
            return
        if not CSR.parse(csr):
            self.die(r, r.BadCSR)
            return
        digest_data = "(%d) (%s) (%s)" % (timestamp, recipient, csr)
        if CSR.verify(CSR.pubkey(csr), digest_data, sig) == False:
            self.die(r, r.BadSignature)
            return
        if not CSR.csr_goodkey(csr):
            self.die(r, r.UnsafeKey)
            return
        names = CSR.subject_names(csr)
        if len(names) == 0:
            self.die(r, r.BadCSR)
            return
        for san in names:  # includes CN as well as SANs
            if not safe("hostname", san) or not CSR.can_sign(san):
                # TODO: Is there a problem including client-supplied data in the URL?
                self.die(r, r.CannotIssueThatName, uri="https://ca.example.com/failures/name?%s" % san)
                return
        # Phew!
        self.add_request(csr, names)
        # This version is relying on an external daemon process to create
        # the challenges.  If we want to create them ourselves, we have to
        # do what the daemon does, and then return the challenges instead
        # of returning proceed.
        r.proceed.timestamp = int(time.time())
        r.proceed.polldelay = 10

    def handleexistingsession(self, m, r):
        if m.request.IsInitialized():
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/requestinexistingsession")
            return
        # The caller has verified that this session exists and is live.
        # If we have no state, something is crazy (maybe a race from two
        # instances of the client?).
        state = self.state()
        if state is None:
            self.die(r, r.BadRequest, uri="https://ca.example.com/failures/uninitializedsession")
            return
        # If we're in makechallenge or issue, tell the client to come back later.
        if state == "makechallenge" or state == "issue":
            r.proceed.timestamp = int(time.time())
            r.proceed.polldelay = 10
            return
        # If we're in testchallenge, tell the client about the challenges and their
        # current status.
        if state == "testchallenge":
            self.send_challenges(m, r)
            return
        # If we're in done, tell the client about the successfully issued cert.
        if state == "done":
            self.send_cert(m, r)
            return
        # Unknown session status.
        self.die(r, r.BadRequest, uri="https://ca.example.com/failures/internalerror")
        return
        # TODO: Process challenge-related messages from the client.

    def die(self, r, reason, uri=None):
        self.kill()
        r.failure.cause = reason
        if uri: r.failure.URI = uri

    def handleclientfailure(self, m, r):
        if r.failure.IsInitialized(): return
        if m.failure.IsInitialized():
            # Received failure message from client!
            self.die(r, r.AbandonedRequest)

    def send_challenges(self, m, r):
        if r.failure.IsInitialized(): return
        # TODO: This needs a more sophisticated notion of success/failure.
        for c in self.challenges():
            # Currently, we can only handle challenge type 0 (dvsni)
            # TODO: unify names "succeeded" vs. "satisfied"?
            if int(c["type"]) != 0:
                self.die(r, r.BadRequest, uri="https://ca.example.com/failures/internalerror")
                return
            chall = r.challenge.add()
            chall.type = int(c["type"])
            chall.name = c["name"]
            chall.succeeded = (c["satisfied"] == "True")   # TODO: this contradicts comment in protocol about meaning of "succeeded"
            # Calculate y
            dvsni_r = c["dvsni:r"]
            bio = M2Crypto.BIO.MemoryBuffer(self.pubkey())
            pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
            y = pubkey.public_encrypt(dvsni_r, M2Crypto.RSA.pkcs1_oaep_padding)
            # In dvsni, we send nonce, y, ext
            chall.data.append(c["dvsni:nonce"])
            chall.data.append(y)
            chall.data.append(c["dvsni:ext"])

    def POST(self):
        web.header("Content-type", "application/x-protobuf+chocolate")
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

        self.handleclientfailure(m, r)

        self.handlesession(m, r)

        # TODO: perhaps some code belongs here to enforce rules about which
        # combinations of protocol messages can occur together in the reply.
        # I think the rules are: server must send exactly one of failure,
        # proceed, challenge, or success; server may not send request or
        # completedchallenge [although we know it never attempts to].
        # If, for some reason, the server is trying to send more than one
        # of these messages, or no message at all, that's an error and the
        # response should be cleared and we should self.die(r, r.BadRequest)
        # or similar.

        # Send reply
        return r.SerializeToString()

    def GET(self):
        web.header("Content-type", "text/html")
        return "Hello, world!  This server only accepts POST requests.\r\n"

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
