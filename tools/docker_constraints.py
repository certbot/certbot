#!/usr/bin/env python
"""Generates constraints file to pin dependency versions in Docker images.

Removes hashes from supplied requirements file and merges it with existing
constraints file. Versions in requirements take precedence over constraints.

Generates interstitial with hashes stripped from requirements.
"""

import sys

import pip_install
import merge_requirements

def main(hashed_reqs_in, unhashed_reqs_out,
         constraints_in, constraints_out):
    with open(unhashed_reqs_out, 'w') as fd:
        fd.write(pip_install.remove_requirements_hashes(hashed_reqs_in))
    with open(constraints_out, 'w') as fd:
        fd.write(merge_requirements.main(constraints_in, unhashed_reqs_out))

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
