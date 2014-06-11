#!/usr/bin/env python

import string


DEFAULT_POLICY_FILE = "/etc/postfix/starttls_everywhere_policy"
POLICY_CF_ENTRY="texthash:" + DEFAULT_POLICY_FILE

def parse_line(line_data):
  "return the and right hand sides of stripped, non-comment postfix config line"
  # lines are like: 
  # smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
  num,line = line_data
  left, sep, right = line.partition("=")
  if not sep:
    return None
  return (num, left.strip(), right.strip())

#def get_cf_values(lines, var):

class MTAConfigGenerator:
  def __init__(self, policy_config):
    self.policy_config = policy_config

class ExistingConfigError(ValueError): pass

class PostfixConfigGenerator(MTAConfigGenerator):
  def __init__(self, policy_config, fixup=False):
    self.fixup = fixup
    MTAConfigGenerator.__init__(self, policy_config)
    self.postfix_cf_file = self.find_postfix_cf()
    self.wrangle_existing_config()
    self.set_domainwise_tls_policies()

  def ensure_cf_var(self, var, ideal, also_acceptable):
    """
    Ensure that existing postfix config @var is in the list of @acceptable
    values; if not, set it to the ideal value.  """

    acceptable = [ideal] + also_acceptable

    l = [(num,line) for num,line in enumerate(self.cf) if line.startswith(var)]
    if not any(l):
      self.additions.append(var + " = " + ideal)
    else:
      values = map(parse_line, l)
      if len(set(values)) > 1:
        if self.fixup:
          #print "Scheduling deletions:" + `values`
          conflicting_lines = [num for num,_var,val in values]
          self.deletions.extend(conflicting_lines)
          self.additions.append(var + " = " + ideal)
        else:
          raise ExistingConfigError, "Conflicting existing config values " + `l`
      val = values[0][2]
      if val not in acceptable:
        #print "Scheduling deletions:" + `values`
        if self.fixup:
          self.deletions.append(values[0][0])
          self.additions.append(var + " = " + ideal)
        else:
          raise ExistingConfigError, "Existing config has %s=%s"%(var,val)
    
  def wrangle_existing_config(self):
    """
    Try to ensure/mutate that the config file is in a sane state.
    Fixup means we'll delete existing lines if necessary to get there.
    """
    self.additions = []
    self.deletions = []
    self.fn = self.find_postfix_cf()
    self.raw_cf = open(self.fn).readlines()
    self.cf = map(string.strip, self.raw_cf)
    #self.cf = [line for line in cf if line and not line.startswith("#")]

    # Check we're currently accepting inbound STARTTLS sensibly
    self.ensure_cf_var("smtpd_use_tls", "yes", [])
    # Ideally we use it opportunistically in the outbound direction
    self.ensure_cf_var("smtp_tls_security_level", "may", ["encrypt"])
    # Maximum verbosity lets us collect failure information
    self.ensure_cf_var("smtp_tls_loglevel", "1", [])
    # Inject a reference to our per-domain policy map
    self.ensure_cf_var("smtp_tls_policy_maps", POLICY_CF_ENTRY, [])

    self.maybe_add_config_lines()

  def maybe_add_config_lines(self):
    if not self.additions:
      return
    if self.fixup:
      print "Deleting lines:", self.deletions
    self.additions[:0]=["#","# New config lines added by STARTTLS Everywhere","#"]
    new_cf_lines = "\n".join(self.additions) + "\n"
    print "Adding to %s:" % self.fn
    print new_cf_lines
    if self.raw_cf[-1][-1] == "\n":     sep = ""
    else:                               sep = "\n"

    self.new_cf = ""
    for num, line in enumerate(self.raw_cf):
      if self.fixup and num in self.deletions:
        self.new_cf += "# Line removed by STARTTLS Everywhere\n# " + line
      else:
        self.new_cf += line
    self.new_cf += sep + new_cf_lines

    print self.new_cf
    f = open(self.fn, "w")
    f.write(self.new_cf)
    f.close()

  def find_postfix_cf(self):
    "Search far and wide for the correct postfix configuration file"
    return "/etc/postfix/main.cf"

  def set_domainwise_tls_policies(self):
    self.policy_lines = []
    for domain, policy in self.policy_config.tls_policies.items():
      entry = domain + " encrypt"
      if "min-tls-version" in policy:
        entry += " " + policy["min-tls-version"]
      self.policy_lines.append(entry)

    f = open(DEFAULT_POLICY_FILE, "w")
    f.write("\n".join(self.policy_lines) + "\n")
    f.close()

if __name__ == "__main__":
  import ConfigParser
  c = ConfigParser.Config("starttls-everywhere.json")
  pcgen = PostfixConfigGenerator(c, fixup=True)
