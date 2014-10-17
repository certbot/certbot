#!/usr/bin/python2.7
import re
import sys
import collections
import argparse

import ConfigParser

# TODO: There's more to be learned from postfix logs!  Here's one sample
# observed during failures from the sender vagrant vm:

# Jun  6 00:21:31 precise32 postfix/smtpd[3648]: connect from localhost[127.0.0.1]
# Jun  6 00:21:34 precise32 postfix/smtpd[3648]: lost connection after STARTTLS from localhost[127.0.0.1]
# Jun  6 00:21:34 precise32 postfix/smtpd[3648]: disconnect from localhost[127.0.0.1]
# Jun  6 00:21:56 precise32 postfix/master[3001]: reload -- version 2.9.6, configuration /etc/postfix
# Jun  6 00:22:01 precise32 postfix/pickup[3674]: AF3B6480475: uid=0 from=<root>
# Jun  6 00:22:01 precise32 postfix/cleanup[3680]: AF3B6480475: message-id=<20140606002201.AF3B6480475@sender.example.com>
# Jun  6 00:22:01 precise32 postfix/qmgr[3673]: AF3B6480475: from=<root@sender.example.com>, size=576, nrcpt=1 (queue active)
# Jun  6 00:22:01 precise32 postfix/smtp[3682]: SSL_connect error to valid-example-recipient.com[192.168.33.7]:25: -1
# Jun  6 00:22:01 precise32 postfix/smtp[3682]: warning: TLS library problem: 3682:error:140740BF:SSL routines:SSL23_CLIENT_HELLO:no protocols available:s23_clnt.c:381:
# Jun  6 00:22:01 precise32 postfix/smtp[3682]: AF3B6480475: to=<vagrant@valid-example-recipient.com>, relay=valid-example-recipient.com[192.168.33.7]:25, delay=0.06, delays=0.03/0.03/0/0, dsn=4.7.5, status=deferred (Cannot start TLS: handshake failure)
#
# Also:
# Oct 10 19:12:13 sender postfix/smtp[1711]: 62D3F481249: to=<vagrant@valid-example-recipient.com>, relay=valid-example-recipient.com[192.168.33.7]:25, delay=0.07, delays=0.03/0.01/0.03/0, dsn=4.7.4, status=deferred (TLS is required, but was not offered by host valid-example-recipient.com[192.168.33.7])
def get_counts(input, config):
  seen_trusted = False

  counts = collections.defaultdict(lambda: collections.defaultdict(int))
  tls_deferred = collections.defaultdict(int)
  # Typical line looks like:
  # Jun 12 06:24:14 sender postfix/smtp[9045]: Untrusted TLS connection established to valid-example-recipient.com[192.168.33.7]:25: TLSv1.1 with cipher AECDH-AES256-SHA (256/256 bits)
  # indicate a problem that should be alerted on.
  # ([^[]*) <--- any group of characters that is not "["
  # Log lines for when a message is deferred for a TLS-related reason. These
  deferred_re = re.compile("relay=([^[]*).* status=deferred.*TLS")
  # Log lines for when a TLS connection was successfully established. These can
  # indicate the difference between Untrusted, Trusted, and Verified certs.
  connected_re = re.compile("([A-Za-z]+) TLS connection established to ([^[]*)")
  for line in sys.stdin:
    deferred = deferred_re.search(line)
    connected = connected_re.search(line)
    if connected:
      validation = connected.group(1)
      mx_hostname = connected.group(2).lower()
      if validation == "Trusted" or validation == "Verified":
        seen_trusted = True
      address_domains = config.get_address_domains(mx_hostname)
      if address_domains:
        for d in address_domains:
          counts[d][validation] += 1
          counts[d]["all"] += 1
    elif deferred:
      mx_hostname = deferred.group(1).lower()
      tls_deferred[mx_hostname] += 1
  if not seen_trusted:
    # Postfix will only emit 'Trusted' if the certificate validates according to
    # the set of trust roots (CA certs) configured in smtp_tls_CAfile.
    print "Didn't see any trusted connections. Need to install some trust roots?"
  return (counts, tls_deferred, seen_trusted)

def print_summary(counts):
  for mx_hostname, validations in counts.items():
    for validation, validation_count in validations.items():
      if validation == "all":
        continue
      print mx_hostname, validation, validation_count / validations["all"], "of", validations["all"]

if __name__ == "__main__":
  arg_parser = argparse.ArgumentParser(description='This is a PyMOTW sample program')
  arg_parser.add_argument('-c', action="store_true", dest="cron", default=False)
  args = arg_parser.parse_args()

  config = ConfigParser.Config("starttls-everywhere.json")
  (counts, tls_deferred, seen_trusted) = get_counts(sys.stdin, config)

  # If not running in cron, print an overall summary of log lines seen from known hosts.
  if not args.cron:
    print_summary(counts)
    if not seen_trusted:
      print 'No Trusted connections seen! Probably need to install a CAfile.'

  if len(tls_deferred) > 0:
    print "Some mail was deferred due to TLS problems:"
    print tls_deferred
