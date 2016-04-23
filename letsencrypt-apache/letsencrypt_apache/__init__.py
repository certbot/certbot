"""Let's Encrypt Apache plugin."""
import sys


import certbot_apache


sys.modules['letsencrypt_apache'] = certbot_apache
