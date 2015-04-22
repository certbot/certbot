#!/usr/bin/env python

import configobj

from letsencrypt.client import renewer

DEFAULTS = configobj.ConfigObj("renewal.conf")
DEFAULTS["renewal_configs_dir"] = "/tmp/etc/letsencrypt/configs"
DEFAULTS["official_archive_dir"] = "/tmp/etc/letsencrypt/archive"
DEFAULTS["live_dir"] = "/tmp/etc/letsencrypt/live"

if __name__ == 'main':
    if ("renewer_enabled" in DEFAULTS
            and not DEFAULTS.as_bool("renewer_enabled")):
        print "Renewer is disabled by configuration!  Exiting."
        raise SystemExit
    else:
        renewer.main()
