#!/usr/bin/env python

import pygeoip, random
geoip = pygeoip.GeoIP('GeoIP.dat', pygeoip.MEMORY_CACHE)

allrouters = []
exits = []
by_country = {}

for L in open("/var/lib/tor/cached-consensus"):
    if L.startswith("s "):
        flags = L.strip().split()
        if "Exit" in flags and "BadExit" not in flags and "Running" in flags and "Valid" in flags and "Stable" in flags:
            exits.append((router[1], router[6], flags))
    if L.startswith("r "):
        router = L.strip().split()
        allrouters.append(router[1])

duplicates = set(e[0] for e in exits if allrouters.count(e[0]) != 1)

for exit in exits:
    name, ip, flags = exit
    if name not in duplicates:
        by_country.setdefault(geoip.country_code_by_addr(ip), []).append(name)
