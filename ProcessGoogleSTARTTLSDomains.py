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
for (address_suffix, hostname_suffix, direction, region, fraction_encrypted) in csvreader:
  if direction == "outbound":
    try:
      d[address_suffix].add(float(fraction_encrypted))
    except ValueError:
      pass

for address_suffix, fraction_encrypted in d.iteritems():
  if min(fraction_encrypted) >= 0.99:
    print min(fraction_encrypted), address_suffix
