"""
The `~certbot_dns_cloudflare.dns_cloudflare` plugin automates the process of
completing a `dns-01` challenge (`~acme.challenges.DNS01`) using the Cloudflare
API.


Credentials
-----------

Use of this plugin requires a configuration file containing Cloudflare API
credentials, obtained from your Cloudflare
`account page <https://www.cloudflare.com/a/account/my-account>`_.

.. code-block:: ini
   :name: credentials.ini
   :caption: Example credentials file:

   # Cloudflare API credentials used by Certbot
   dns_cloudflare_email = cloudflare@example.com
   dns_cloudflare_api_key = 0123456789abcdef0123456789abcdef01234567

The path to this file can be provided interactively or using the
`--dns-cloudflare-credentials` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   Cloudflare account. Users who can read this file can use these credentials
   to issue API calls on your behalf. Users who can cause Certbot to run using
   these credentials can complete a `dns-01` challenge to acquire new
   certificates or revoke existing certificates for associated domains.



"""
