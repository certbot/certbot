"""Tools for submitting server configurations."""
import sys


import letshelp_certbot


sys.modules['letshelp_letsencrypt'] = letshelp_certbot
