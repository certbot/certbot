#!/usr/bin/env python

import os
import re
import sys

def main(args):
    out_lines = []
    for line in args:
        search = re.search(r'^(\S*==\S*).*$', line)
        if search:
            out_lines.append(search.group(1))
    return os.linesep.join(out_lines)

if __name__ == '__main__':
    print(main(sys.argv[1:]))
