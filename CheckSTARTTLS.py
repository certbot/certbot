#!/usr/bin/python
import sys
import os
import errno
import smtplib
import socket
import subprocess
import re
import json
import collections

import dns.resolver
from M2Crypto import X509
from publicsuffix import PublicSuffixList

public_suffix_list = PublicSuffixList()
CERTS_OBSERVED = 'certs-observed'

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def extract_names(pem):
    """Return a set of DNS subject names from PEM-encoded leaf cert."""
    leaf = X509.load_cert_string(pem, X509.FORMAT_PEM)

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
  """Attempt a STARTTLS connection with openssl and save the output."""
  if supports_starttls(mx_host):
    # smtplib doesn't let us access certificate information,
    # so shell out to openssl.
    try:
      output = subprocess.check_output(
          """openssl s_client \
             -starttls smtp -connect %s:25 -showcerts </dev/null \
             2>/dev/null
             """ % mx_host, shell = True)
    except subprocess.CalledProcessError:
      print "Failed s_client"
      return

    # Save a copy of the certificate for later analysis
    with open(os.path.join(CERTS_OBSERVED, mail_domain, mx_host), "w") as f:
      f.write(output)

def valid_cert(filename):
  """Return true if the certificate is valid.

     Note: CApath must have hashed symlinks to the trust roots.
     TODO: Include the -attime flag based on file modification time."""

  if open(filename).read().find("-----BEGIN CERTIFICATE-----") == -1:
    return False
  try:
    # The file contains both the leaf cert and any intermediates, so we pass it
    # as both the cert to validate and as the "untrusted" chain.
    output = subprocess.check_output("""openssl verify -CApath /home/jsha/mozilla/ -purpose sslserver \
              -untrusted "%s" \
              "%s"
             """ % (filename, filename), shell = True)
    return True
  except subprocess.CalledProcessError:
    return False

def check_certs(mail_domain):
  """
  Return "" if any certs for any mx domains pointed to by mail_domain
  were invalid, and a public suffix for one if they were all valid
  """
  dir = os.path.join(CERTS_OBSERVED, mail_domain)
  if not os.path.exists(dir):
    collect(mail_domain)
  names = set()
  for mx_hostname in os.listdir(dir):
    filename = os.path.join(dir, mx_hostname)
    if not valid_cert(filename):
      return ""
    else:
      new_names = extract_names_from_openssl_output(filename)
      new_names = set(public_suffix_list.get_public_suffix(n) for n in new_names)
      names.update(new_names)
  if len(names) >= 1:
    # Hack: Just pick an arbitrary suffix for now. Do something cleverer later.
    return names.pop()
  else:
    return ""

def common_suffix(hosts):
  num_components = min(len(h.split(".")) for h in hosts)
  longest_suffix = ""
  for i in range(1, num_components + 1):
    suffixes = set(".".join(h.split(".")[-i:]) for h in hosts)
    if len(suffixes) == 1:
      longest_suffix = suffixes.pop()
    else:
      return longest_suffix
  return longest_suffix

def extract_names_from_openssl_output(certificates_file):
  openssl_output = open(certificates_file, "r").read()
  cert = re.findall("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", openssl_output, flags = re.DOTALL)
  return extract_names(cert[0])

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
  except smtplib.SMTPException, e:
    # In order to talk to some hosts, you need to run this from a host that has a
    # reverse DNS entry. AWS instances all have reverse DNS, as an example.
    if e[0] == 554:
      print e[1]
    else:
      print "No STARTTLS support on %s" % mx_host, e[0]
    return False

def min_tls_version(mail_domain):
  protocols = []
  for mx_hostname in os.listdir(os.path.join(CERTS_OBSERVED, mail_domain)):
    filename = os.path.join(CERTS_OBSERVED, mail_domain, mx_hostname)
    contents = open(filename).read()
    protocol = re.findall("Protocol  : (.*)", contents)[0]
    protocols.append(protocol)
  return min(protocols)

def collect(mail_domain):
  """
  Attempt to connect to each MX hostname for mail_doman and negotiate STARTTLS.
  Store the output in a directory with the same name as mail_domain to make
  subsequent analysis faster.
  """
  print "Checking domain %s" % mail_domain
  mkdirp(os.path.join(CERTS_OBSERVED, mail_domain))
  answers = dns.resolver.query(mail_domain, 'MX')
  for rdata in answers:
      mx_host = str(rdata.exchange).rstrip(".")
      tls_connect(mx_host, mail_domain)

if __name__ == '__main__':
  """Consume a target list of domains and output a configuration file for those domains."""
  if len(sys.argv) < 2:
    print("Usage: CheckSTARTTLS.py list-of-domains.txt > output.json")

  config = collections.defaultdict(dict)

  for input in sys.argv[1:]:
    for domain in open(input).readlines():
      domain = domain.strip()
      suffix = check_certs(domain)
      if suffix != "":
        min_version = min_tls_version(domain)
        suffix_match = "." + suffix
        config["acceptable-mxs"][domain] = {
          "accept-mx-domains": [suffix_match]
        }
        config["tls-policies"][suffix_match] = {
          "require-tls": True,
          "min-tls-version": min_version
        }

  print json.dumps(config, indent=2, sort_keys=True)
