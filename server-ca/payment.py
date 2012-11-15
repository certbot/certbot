#!/usr/bin/env python

# TODO: Is there some way to limit this program's access to the database
# so that it cannot change any values, but can still publish pubsub
# messages?  That would make the security analysis of the system as a
# whole clearer.

import web, redis

urls = (
     '/(.*)', 'payment'
)

r = redis.Redis()

def hexdigit(s):
    return s in "0123456789abcdef"

class payment(object):
    def GET(self, session):
        web.header("Content-type", "text/html")
        if len(session) != 64 or not all(hexdigit(s) for s in session):
            return "Attempt to process payment for invalid session."
        if session not in r or r.hget(self.id, "live") != "True":
            return "Attempt to process payment for invalid session."
        if r.hget(session, "state") != "payment":
            return "Attempt to process payment for session not expecting it."
        r.publish("payments", session)
        return "<h1>Thank you!</h1> Processed a payment for session ID %s." % session

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()

# vim: set tabstop=4 shiftwidth=4 expandtab
