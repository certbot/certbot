#!/usr/bin/env python

import web
from Crypto.Hash import SHA256, HMAC
from chocolate_protocol_pb2 import chocolatemessage
from google.protobuf.message import DecodeError

def hmac(k, m):
    return HMAC.new(k, m, SHA256).hexdigest()

urls = (
     '.*', 'index'
)

class index:
    def GET(self):
        web.header("Content-type", "text/html")
        return "Hello, world!  This server only accepts POST requests."

    def POST(self):
        web.header("Content-type", "application/x-protobuf")
        web.setcookie("chocolate", hmac("foo", "bar"),
                       secure=True) # , httponly=True)
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
        if m.debug:
            web.header("Content-type", "text/plain")
            return "SAW MESSAGE: %s\n" % str(r)
        else:
            return r.SerializeToString()

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
