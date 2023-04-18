#!/usr/bin/env python
"""A Certbot hook for probing."""
import os
import sys

hook_script_type = os.path.basename(os.path.dirname(sys.argv[1]))
if hook_script_type == 'deploy' and ('RENEWED_DOMAINS' not in os.environ
                                     or 'RENEWED_LINEAGE' not in os.environ):
    sys.stderr.write('Environment variables not properly set!\n')
    sys.exit(1)

print(hook_script_type)
