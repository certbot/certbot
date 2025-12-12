#!/usr/bin/env python

import os
import sys

from certbot._internal.nginx import nginxparser


def roundtrip(stuff):
    success = True
    for t in stuff:
        print(t)
        if not os.path.isfile(t):
            continue
        with open(t, "r") as f:
            config = f.read()
            try:
                if nginxparser.dumps(nginxparser.loads(config)) != config:
                    print("Failed parsing round-trip for {0}".format(t))
                    success = False
            except Exception as e:
                print("Failed parsing {0} ({1})".format(t, e))
                success = False
    return success

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s directory" % sys.argv[0])
        sys.exit(1)
    success = True
    for where, _, files in os.walk(sys.argv[1]):
        if files:
            success &= roundtrip(os.path.join(where, f) for f in files)

    sys.exit(0 if success else 1)
