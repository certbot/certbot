#!/usr/bin/env python
"""Removes hash information from requirement files passed to it as file path
arguments or simply piped to stdin."""

import re
import sys


def process_entries(entries):
    """Strips off hash strings from dependencies.

    :param list entries: List of entries

    :returns: list of dependencies without hashes
    :rtype: list
    """
    out_lines = []
    for e in entries:
        e = e.strip()
        search = re.search(r'^(\S*==\S*).*$', e)
        if search:
            out_lines.append(search.group(1))
    return out_lines

def main(*paths):
    """
    Reads dependency definitions from a (list of) file(s) provided on the
    command line. If no command line arguments are present, data is read from
    stdin instead.

    Hashes are removed from returned entries.
    """

    deps = []
    if paths:
        for path in paths:
            with open(path) as file_h:
                deps += process_entries(file_h.readlines())
    else:
        # Need to check if interactive to avoid blocking if nothing is piped
        if not sys.stdin.isatty():
            stdin_data = []
            for line in sys.stdin:
                stdin_data.append(line)
            deps += process_entries(stdin_data)

    return "\n".join(deps)

if __name__ == '__main__':
    print(main(*sys.argv[1:]))  # pylint: disable=star-args
