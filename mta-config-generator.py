#!/usr/bin/env python

import string

DEFAULT_POLICY_FILE = "texthash:/etc/postfix/starttls_everywhere_policy"

def parse_line(self, line_data):
  "return the and right hand sides of stripped, non-comment postfix config line"
  # lines are like: 
  # smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
  num,line = line_data
  left, sep, right = line.partition("=")
  if not sep:
    return None
  return (left.strip(), right.strip())

#def get_cf_values(lines, var):

class MTAConfigGenerator:
  def __init__(self, stlse_config):
    self.c = stlse_config

class ExistingConfigError(ValueError): pass

class PostfixConfigGenerator(MTAConfigGenerator):
  def __init__(self, stlse_config):
    MTAConfigGenerator.__init__(self, stlse_config)
    this.postfix_cf_file = this.find_postfix_cf()
    this.wrangle_existing_config()

  def ensure_cf_var(self, var, ideal, also_acceptable):
    """
    Ensure that existing postfix config @var is in the list of @acceptable
    values; if not, set it to the ideal value.  """

    acceptable = [ideal] + also_acceptable

    l = [num,line for num,line in enumerate(cf) if line.startswith(var)]
    if not any(l):
      this.additions.append("smtpd_use_tls = yes")
    else:
      values = [right for left, right in map(parse_line, l)]
      if len(set(values)) > 1:
        if this.fixup:
          this.deletions.append(
        raise ExistingConfigError, "Conflicting existing config values " + `l`
      if values[0] != "yes":
    
  def wrangle_existing_config(self, fixup=false):
    """
    Try to ensure/mutate that the config file is in a sane state.
    Fixup means we'll delete existing lines if necessary to get there.
    """
    this.additions = []
    fn = find_postfix_cf()
    raw_cf = open(fn).readlines()
    this.cf = map(string.strip, raw_cf)
    #this.cf = [line for line in cf if line and not line.startswith("#")]
    this.fixup = fixup

    # Check we're currently accepting inbound STARTTLS sensibly
    this.ensure_cf_var("smtpd_use_tls", "yes", [])
    # Ideally we use it opportunistically in the outbound direction
    this.ensure_cf_var("smtp_tls_security_level", "may", ["encrypt"])
    # Maximum verbosity lets us collect failure information
    this.ensure_cf_var("smtp_tls_loglevel", "1", [])
    # Inject a reference to our per-domain policy map
    this.ensure_cf_var("smtp_tls_policy_maps", DEFAULT_POLICY_FILE, [])

    this.maybe_add_config_lines()

  def maybe_add_config_lines(self):
    if not this.additions:
      return
    this.additions[:0]=["","# New config lines added by STARTTLS Everywhere",""]
    new_cf_lines = "\n".join(this.additions)
    print "Adding to %s:" % fn
    print new_cf_lines
    if raw_cf[-1][-1] == "\n":     sep = ""
    else:                          sep = "\n"
    new_cf = "".join(raw_cf) + sep + new_cf_lines
    f = open(fn, "w").write(new_cf)
    f.close()

  def find_postfix_cf(self):
    "Search far and wide for the correct postfix configuration file"
    return "/etc/postfix/main.cf"
