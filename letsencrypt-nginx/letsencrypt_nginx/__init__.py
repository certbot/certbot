"""Let's Encrypt Nginx plugin."""
import sys


import certbot_nginx


sys.modules['letsencrypt_nginx'] = certbot_nginx
