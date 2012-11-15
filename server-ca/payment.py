#!/usr/bin/env python

import web, redis

urls = (
     '.*', 'payment'
)

r = redis.Redis()

class payment(object):
    def GET(self):
        web.header("Content-type", "text/html")
        s = ""
        try: s = web.data()
        except: pass
        return "Hello there! " + s

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()

# vim: set tabstop=4 shiftwidth=4 expandtab
