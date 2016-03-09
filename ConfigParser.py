#!/usr/bin/env python

import sys
import json
from datetime import datetime
import string
import collections

def parse_timestamp(ts):
  try:
    int(ts)
    dt = datetime.fromtimestamp(ts)
    return dt
  except:
    raise ValueError, "Invalid timestamp integer: " + `ts`

legal = string.letters + string.digits + ".-"
known_tlds =["com","org","net","biz","info",] # xxx make me from an ICANN list
def looks_like_a_domain(s):
  "Return true if string looks like a domain, as best we can tell..."
  global known_tlds
  try:
    domain = s.lower()
    assert domain[0].islower()
    assert all([c in legal for c in domain])
    tld = s.split(".")[-1]
    if tld not in known_tlds:
      # XXX perform DNS query to determine that this TLD exists
      pass
    return True
  except:
    return False

class Config:
  def __init__(self, cfg_file_name = "config.json"):
    f = open(cfg_file_name)
    self.cfg = json.loads(f.read())
    self.tls_policies = {}
    self.mx_map = {}
    for atr, val in self.cfg.items():
      # Verify each attribute of the structure
      if atr.startswith("comment"):
        continue
      if atr == "author":
        if type(val) not in [str, unicode]:
          raise TypeError, "Author must be a string: " + `val`
      elif atr == "timestamp":
        self.timestamp = parse_timestamp(val)
      elif atr == "expires":
        self.expires = parse_timestamp(val)
      elif atr == "tls-policies":
        for domain, policies in self.check_tls_policy_domains(val):
          if type(policies) != dict:
            raise TypeError, domain + "'s policies should be a dict: " + `policies`
          self.tls_policies[domain] = {} # being here enforces TLS at all
          for policy, v in policies.items():
            value = str(v).lower()
            if policy == "require-tls":
              if value in ("true", "1", "yes"):
                self.tls_policies[domain]["required"] = True
              elif value in ("false", "0", "no"):
                self.tls_policies[domain]["required"] = False
              else:
                raise ValueError, "Unknown require-tls value " + `value`
            elif policy == "min-tls-version":
              reasonable = ["TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
              reasonable = map(string.lower, reasonable)
              if not value in reasonable:
                raise ValueError, "Not a valid TLS version string: " + `value`
              self.tls_policies[domain]["min-tls-version"] = str(value)
            elif policy == "enforce-mode":
              if value == "enforce":
                self.tls_policies[domain]["enforce"] = True
              elif value == "log-only":
                self.tls_policies[domain]["enforce"] = False
              else:
                raise ValueError, "Not a known enoforcement policy " + `value`
      elif atr == "acceptable-mxs":
        self.acceptable_mxs = val
        self.mx_domain_to_address_domains = collections.defaultdict(set)
        for address_domain, properties in self.acceptable_mxs.items():
          mx_list = properties["accept-mx-domains"]
          if len(mx_list) > 1:
            print "Lists of multiple accept-mx-domains not yet supported, skipping ", address_domain
          mx_domain = mx_list[0]
          self.mx_domain_to_address_domains[mx_domain].add(address_domain)
        pass
      else:
        sys.stderr.write("Unknown attribute: " + `atr` + "\n")
    # XXX is it ever permissible to have a domain with an acceptable-mx 
    # that does not point to a TLS security policy?  If not, check/warn/fail
    # here

  def get_address_domains(self, mx_hostname):
    labels = mx_hostname.split(".")
    for n in range(1, len(labels)):
      parent = "." + ".".join(labels[n:])
      if parent in self.mx_domain_to_address_domains:
        return self.mx_domain_to_address_domains[parent]
    return None

  def check_tls_policy_domains(self, val):
    if type(val) != dict:
      raise TypeError, "tls-policies should be a dict" + `val`
    for domain, policies in val.items():
      try:
        assert type(domain) == unicode
        d = str(domain) # convert from unicode
      except:
        raise TypeError, "tls-policy domain not a string" + `domain`
      yield (d, policies)

if __name__ == "__main__":
  c = Config()
