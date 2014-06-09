#!/usr/bin/python
import sys
import os
import errno
import smtplib
import socket
import subprocess
import re
import json

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
    """Return a list of DNS subject names from PEM-encoded leaf cert."""
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
    with open(os.path.join(mail_domain, mx_host), "w") as f:
      f.write(output)

def valid_cert(filename):
  """Return true if the certificate is valid.

     Note: CApath must have hashed symlinks to the trust roots.
     TODO: Include the -attime flag based on file modification time."""

  if open(filename).read().find("-----BEGIN CERTIFICATE-----") == -1:
    return False
  try:
    output = subprocess.check_output("""openssl verify -CApath /home/jsha/mozilla/ -purpose sslserver \
              -untrusted "%s" \
              "%s"
             """ % (filename, filename), shell = True)
    return True
  except subprocess.CalledProcessError:
    return False

def check_certs(mail_domain):
  names = set()
  for mx_hostname in os.listdir(mail_domain):
    filename = os.path.join(mail_domain, mx_hostname)
    if not valid_cert(filename):
      return ""
    else:
      new_names = extract_names_from_openssl_output(filename)
      names.update(new_names)
      names.add(filename.rstrip("."))
  if len(names) >= 1:
    return common_suffix(names)
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
  except smtplib.SMTPException:
    print "No STARTTLS support on %s" % mx_host
    return False

def min_tls_version(mail_domain):
  protocols = []
  for mx_hostname in os.listdir(mail_domain):
    filename = os.path.join(mail_domain, mx_hostname)
    contents = open(filename).read()
    protocol = re.findall("Protocol  : (.*)", contents)[0]
    protocols.append(protocol)
  return min(protocols)

def collect(mail_domain):
  mkdirp(mail_domain)
  answers = dns.resolver.query(mail_domain, 'MX')
  for rdata in answers:
      mx_host = str(rdata.exchange).rstrip(".")
      tls_connect(mx_host, mail_domain)

if __name__ == '__main__':
  """Consume a target list of domains and output a configuration file for those domains."""
  if len(sys.argv) == 1:
    print("Please pass at least one mail domain as an argument")

  config = {
    "address-domains": {
    },
    "mx-domains": {
    }
  }
  for domain in sys.argv[1:]:
    #collect(domain)
    if len(os.listdir(domain)) == 0:
      continue
    suffix = check_certs(domain)
    min_version = min_tls_version(domain)
    if suffix != "":
      suffix_match = "*." + suffix
      config["address-domains"][domain] = {
        "accept-mx-domains": [suffix_match]
      }
      config["mx-domains"][suffix_match] = {
        "require-tls": True,
        "min-tls-version": min_version
      }

  print json.dumps(config, indent=2)
