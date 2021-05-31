"""Pynsist extra_preamble for the Certbot entry point.

This preamble ensures that Certbot on Windows always runs with the --preconfigured-renewal
flag set. Since Pynsist creates a Scheduled Task for renewal, we want this flag to be set
so that we can provide the right automated renewal advice to Certbot on Windows users.

"""


import sys

sys.argv += ["--preconfigured-renewal"]
