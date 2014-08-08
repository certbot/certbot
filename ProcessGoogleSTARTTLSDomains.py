#!/usr/bin/python
"""
Process Google's TLS delivery data from
https://www.google.com/transparencyreport/saferemail/data/?hl=en
to look for outbound domains that can negotiate an encrypted
connection >99% of the time.

Usage:
  ./ProcessGoogleSTARTTLSDomains.py google-starttls-domains.csv
"""
import csv
import codecs
import sys
from collections import defaultdict

csvreader = csv.reader(codecs.open(sys.argv[1], "rU", "utf-8"), delimiter=',', quotechar='"')
d = defaultdict(set)
# Google's report doesn't include gmail.com because it's local delivery, but we
# know they support STARTTLS, so manually include them.
d["gmail.com"] = set([1])
for (address_suffix, hostname_suffix, direction, region, region_name, fraction_encrypted) in csvreader:
  if direction == "outbound":
    # Some domains exist in many TLDs and are summarized as, e.g. yahoo.{...}.
    # We're tryingto get a solid list of the relevant TLDs, but in the meantime
    # just use .com.
    address_suffix = address_suffix.replace("{...}", "com")
    try:
      d[address_suffix].add(float(fraction_encrypted))
    except ValueError:
      pass

for address_suffix, fraction_encrypted in d.iteritems():
  if min(fraction_encrypted) >= 0.99:
    print address_suffix
