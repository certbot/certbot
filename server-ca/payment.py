#!/usr/bin/env python

import web, redis

urls = (
     '/(.*)', 'payment'
)

r = redis.Redis()

class payment(object):
    def GET(self, stuff):
        web.header("Content-type", "text/html")
        return "Hello there! " + stuff

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()

# vim: set tabstop=4 shiftwidth=4 expandtab
