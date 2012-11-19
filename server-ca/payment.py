#!/usr/bin/env python

# TODO: Is there some way to limit this program's access to the database
# so that it cannot change any values, but can still publish pubsub
# messages?  That would make the security analysis of the system as a
# whole clearer.

import web, redis

urls = (
     '/([a-f0-9]{10})', 'shortform',
     '/([a-f0-9]{64})', 'form',
     '/submit=([a-f0-9]{64})', 'payment'
)

r = redis.Redis()

class shortform(object):
      def GET(self, what):
          web.header("Content-type", "text/html")
          expanded = r.get("shorturl-%s" % what)
          if not expanded:
              return "<html><h1>Unknown session ID</h1></html>"
          return """
          <html>
          <h1>Payment required</h1>
          Due to certificate authority policy, issuing this certificate requires a payment.
          <p>
          <hr width="70%%" />
          <p>
          A payment of <b>17.00 simoleons</b> is due now.
          <p>
          In order to process this payment, please pretend to enter a 16-digit credit-card
          number below, and then click the Submit Payment button.
          <p>
          <form action="/payment.py/submit=%s" method="GET">
          <i>Credit Card Type</i> <select name=""><option>Vista</option><option>MisterCard</option><option>Discovery</option></select> <br />
          <i>Credit Card Number</i> <input type="text" name="" style="font-family:monospace" autocomplete="off" /><br />
          <input type="submit" value="Submit Payment">
          </form>
          This payment will appear on your
          credit card statement as TRUSTIFIABLE CERTIFICATE SERVICES.
          </html>
          """ % expanded

class form(object):
      def GET(self, what):
          web.header("Content-type", "text/html")
          return """
          <html>
          <h1>Payment required</h1>
          Due to certificate authority policy, issuing this certificate requires a payment.
          <p>
          <hr width="70%%" />
          <p>
          A payment of <b>17.00 simoleons</b> is due now.
          <p>
          In order to process this payment, please pretend to enter a 16-digit credit-card
          number below, and then click the Submit Payment button.
          <p>
          <form action="/payment.py/submit=%s" method="GET">
          <i>Credit Card Type</i> <select name=""><option>Vista</option><option>MisterCard</option><option>Discovery</option></select> <br />
          <i>Credit Card Number</i> <input type="text" name="" style="font-family:monospace" autocomplete="off" /><br />
          <input type="submit" value="Submit Payment">
          </form>
          This payment will appear on your
          credit card statement as TRUSTIFIABLE CERTIFICATE SERVICES.
          </html>
          """ % what

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
        return "<h1>Thank you!</h1> Processed a payment for session ID %s." % session

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()

# vim: set tabstop=4 shiftwidth=4 expandtab
