#!/usr/bin/env python

import web, shelve, time
from Crypto.Hash import SHA256, HMAC
from Crypto import Random 
from chocolate_protocol_pb2 import chocolatemessage
from google.protobuf.message import DecodeError

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
        self.f[session]["live"] = False

    def destroy(self, session):
        del self.f[session]

class index:
    def GET(self):
        web.header("Content-type", "text/html")
        return "Hello, world!  This server only accepts POST requests."

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
        if m.session == "":
            # New session
            r.session = SHA256.new(Random.get_random_bytes(32)).hexdigest()
            session = r.session.encode("UTF8")
            self.sessions.create(session, int(time.time()))
        elif m.session and not r.failure.IsInitialized():
            session = m.session.encode("UTF8")
            r.session = session
            if not self.sessions.exists(session):
                r.failure.cause = r.StaleRequest
            elif not self.sessions.live(session):
                r.failure.cause = r.StaleRequest
        if m.debug:
            web.header("Content-type", "text/plain")
            return "SAW MESSAGE: %s\n" % str(r)
        else:
            return r.SerializeToString()
            

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
