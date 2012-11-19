#!/usr/bin/env python

# TODO: Is there some way to limit this program's access to the database
# so that it cannot change any values, but can still publish pubsub
# messages?  That would make the security analysis of the system as a
# whole clearer.

import web, redis

urls = (
     '/([a-f0-9]{10})', 'shortform',
     '/submit=([a-f0-9]{64})', 'payment'
)

r = redis.Redis()

class shortform(object):
      def GET(self, what):
          web.header("Content-type", "text/html")
          expanded = r.get("shorturl-%s" % what)
          if not expanded:
              return "<html><h1>Unknown session ID</h1></html>"
          with open("index.html","r") as f:
              return f.read() % expanded

def hexdigit(s):
    return s in "0123456789abcdef"

class payment(object):
    def GET(self, session):
        web.header("Content-type", "text/html")
        if len(session) != 64 or not all(hexdigit(s) for s in session):
            return "Attempt to process payment for invalid session."
        if session not in r or r.hget(session, "live") != "True":
            return "Attempt to process payment for invalid session."
        if r.hget(session, "state") != "payment":
            return "Attempt to process payment for session not expecting it."
        r.publish("payments", session)
        with open("thanks.html","r") as f:
            return f.read() % session

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()

# vim: set tabstop=4 shiftwidth=4 expandtab
