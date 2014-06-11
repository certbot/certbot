#!/usr/bin/env python

import sys
import json
from datetime import datetime
import string


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
    for atr, val in self.cfg.items():
      #print atr,val
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
        self.tls_policies = {}
        for domain,policies in self.check_tls_policy_domains(val):
          if type(policies) != dict:
            raise TypeError, domain + "'s policies should be a dict: " + `policies`
          self.tls_policies[domain] = {} # being here enforces TLS at all
          for policy, value in policies.items():
            if policy == "min-tls-version":
              reasonable = ["TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
              if not value in reasonable:
                raise ValueError, "Not a valid TLS version string: " + `value`
              self.tls_policies[domain]["min-tls-version"] = str(value)
      elif atr == "acceptable-mxs":
        pass
      else:
        sys.stderr.write("Uknown attribute: " + `atr` + "\n")
    print self.tls_policies

  def check_tls_policy_domains(self, val):
    if type(val) != dict:
      raise TypeError, "tls-policies should be a dict" + `val`
    for domain, policies in val.items():
      try:
        assert type(domain) == unicode
        d = str(domain) # convert from unicode
      except:
        raise TypeError, "tls-policy domain not a string" + `domain`
      if not d.startswith("*."):
        raise ValueError, "tls-policy domains must start with *.; try *."+d
      d = d.partition("*.")[2]
      if not looks_like_a_domain(d):
        raise ValueError, "tls-policy for something that a domain? " + d
      yield (d, policies)

if __name__ == "__main__":
  c = Config()
