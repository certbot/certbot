#!/usr/bin/python
import sys
import os
import errno
import smtplib
import socket
import subprocess
import re

import dns.resolver
from M2Crypto import X509

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def extract_names(pem):
    leaf = X509.load_cert_string(pem, X509.FORMAT_PEM)

    """Extracts a list of DNS names associated with the leaf cert."""
    subj = leaf.get_subject()
    # Certs have a "subject" identified by a Distingushed Name (DN).
    # Host certs should also have a Common Name (CN) with a DNS name.
    common_names = subj.get_entries_by_nid(subj.nid['CN'])
    common_names = [name.get_data().as_text() for name in common_names]
    try:
        # The SAN extension allows one cert to cover multiple domains
        # and permits DNS wildcards.
        # http://www.digicert.com/subject-alternative-name.htm
        # The field is a comma delimited list, e.g.:
        # >>> twitter_cert.get_ext('subjectAltName').get_value()
        # 'DNS:www.twitter.com, DNS:twitter.com'
        alt_names = leaf.get_ext('subjectAltName').get_value()
        alt_names = alt_names.split(', ')
        alt_names = [name.partition(':') for name in alt_names]
        alt_names = [name for prot, _, name in alt_names if prot == 'DNS']
    except:
        alt_names = []
    return set(common_names + alt_names)

def tls_connect(mx_host, mail_domain):
  if supports_starttls(mx_host):
    # smtplib doesn't let us access certificate information,
    # so shell out to openssl.
    try:
      output = subprocess.check_output(
          """openssl s_client \
             -CApath /usr/share/ca-certificates/mozilla/ \
             -starttls smtp -connect %s:25 -showcerts </dev/null \
             2>/dev/null
             """ % mx_host, shell=True)
    except subprocess.CalledProcessError:
      print "Failed s_client"
      return

    # Save a copy of the certificate for later analysis
    with open(os.path.join(mail_domain, mx_host), "w") as f:
      f.write(output)

    cert = re.findall("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, flags = re.DOTALL)
    if len(cert) > 0:
      names = extract_names(cert[0])
      print "%s certificate -> %s" % (mx_host, ", ".join(names))
      if mx_host in names:
        print "  MATCH"
      else:
        print "  NOMATCH"

def supports_starttls(mx_host):
  try:
    smtpserver = smtplib.SMTP(mx_host, 25, timeout = 2)
    smtpserver.ehlo()
    smtpserver.starttls()
    return True
    print "Success: %s" % mx_host
  except socket.error as e:
    print "Connection to %s failed: %s" % (mx_host, e.strerror)
    return False
  except smtplib.SMTPException:
    print "No STARTTLS support on %s" % mx_host
    return False

def check(mail_domain):
  mkdirp(mail_domain)
  answers = dns.resolver.query(mail_domain, 'MX')
  for rdata in answers:
      mx_host = str(rdata.exchange).rstrip(".")
      tls_connect(mx_host, mail_domain)

if len(sys.argv) == 1:
  print("Please pass at least one mail domain as an argument")

for domain in sys.argv[1:]:
  check(domain)
