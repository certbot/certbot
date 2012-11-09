#!/usr/bin/env python

import exit_geography, random, socks

# This file is currently unused.  It demonstrates how to make a
# connection using exit_geography and a Tor exit node in a chosen
# country.  This can be used to implement multipath probing to
# perform SNI challenges from the vantage point of specified
# countries.

node = random.choice(exit_geography.by_country["DE"])
socksocket = socks.socksocket()
socksocket.setproxy(socks.PROXY_TYPE_SOCKS4, "localhost", 9050)
print node
socksocket.connect(("theobroma.info.%s.exit" % node, 80))
