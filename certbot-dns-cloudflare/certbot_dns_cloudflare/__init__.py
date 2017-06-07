"""Cloudflare DNS Authenticator

This plugin automates the process of completing a dns-01 challenge
(`~acme.challenges.DNS01`) using the Cloudflare API.

Use of this plugin requires a configuration file containing Cloudflare API
credentials, obtained from your Cloudflare
`account page <https://www.cloudflare.com/a/account/my-account>`_.

Example:

.. code-block:: ini

  dns_cloudflare_email = cloudflare@example.com
  dns_cloudflare_api_key = 0123456789abcdef0123456789abcdef01234567

"""
