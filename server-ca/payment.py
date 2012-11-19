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

def log(msg):
        r.publish("logs", msg)

class payment(object):
    def GET(self, session):
        web.header("Content-type", "text/html")
        if len(session) != 64 or not all(hexdigit(s) for s in session):
            return "<html><h1>Oops!</h1>Attempt to process payment for invalid session.</html>"
        if session not in r or r.hget(session, "live") != "True":
            return "<html><h1>Oops!</h1>Attempt to process payment for invalid session.</html>"
        if r.hget(session, "state") != "payment":
            return "<html><h1>Oops!</h1>Attempt to process payment for session that was not expecting it.</html>"
        r.publish("payments", session)
        names = r.lrange("%s:names" % session, 0, -1)
        names_list = '<ul style="font-family:monospace">' + "\n".join("<li>%s</li>" % n for n in names) + '</ul>'
        log("received valid payment details from %s" % web.ctx.ip)
        with open("thanks.html","r") as f:
            return f.read() % (session, names_list)

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()

# vim: set tabstop=4 shiftwidth=4 expandtab
