#!/usr/bin/env python

import sys
import json
from datetime import datetime

def parse_timestamp(ts):
  try:
    int(ts)
    dt = datetime.fromtimestamp(ts)
    return dt
  except:
    raise ValueError, "Invalid timestamp integer: " + `ts`


class Config:
  def __init__(self, cfg_file_name = "config.json"):
    f = open(cfg_file_name)
    cfg = json.loads(f.read())
    for atr, val in cfg.items():
      #print atr,val
      # Parse and verify each attribute of the structure
      if atr.startswith("comment"):
        continue
      if atr == "author":
        if type(val) not in [str, unicode]:
          raise TypeError, "Author must be a string: " + `val`
      elif atr == "timestamp":
        self.timestamp = parse_timestamp(val)
      elif atr == "expires":
        self.expires = parse_timestamp(val)
      elif atr == "address-domains":
        if type(val) != dict:
          raise TypeError, "address-domains " + `val`
      else:
        sys.stderr.write("Uknown attribute: " + `atr` + "\n")

if __name__ == "__main__":
  c = Config()
