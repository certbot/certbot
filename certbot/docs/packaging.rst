===============
Packaging Guide
===============

Releases
========

We release packages and upload them to PyPI (wheels and source tarballs).

- https://pypi.python.org/pypi/acme
- https://pypi.python.org/pypi/certbot
- https://pypi.python.org/pypi/certbot-apache
- https://pypi.python.org/pypi/certbot-nginx
- https://pypi.python.org/pypi/certbot-dns-cloudflare
- https://pypi.python.org/pypi/certbot-dns-cloudxns
- https://pypi.python.org/pypi/certbot-dns-digitalocean
- https://pypi.python.org/pypi/certbot-dns-dnsimple
- https://pypi.python.org/pypi/certbot-dns-dnsmadeeasy
- https://pypi.python.org/pypi/certbot-dns-google
- https://pypi.python.org/pypi/certbot-dns-linode
- https://pypi.python.org/pypi/certbot-dns-luadns
- https://pypi.python.org/pypi/certbot-dns-nsone
- https://pypi.python.org/pypi/certbot-dns-ovh
- https://pypi.python.org/pypi/certbot-dns-rfc2136
- https://pypi.python.org/pypi/certbot-dns-route53

The following scripts are used in the process:

- https://github.com/certbot/certbot/blob/master/tools/release.sh

We use git tags to identify releases, using `Semantic Versioning`_. For
example: `v0.11.1`.

.. _`Semantic Versioning`: http://semver.org/

Notes for package maintainers
=============================

0. Please use our tagged releases, not ``master``!

1. Do not package ``certbot-compatibility-test`` or ``letshelp-certbot`` - it's only used internally.

2. To run tests on our packages, you should use ``python setup.py test``. Doing things like running ``pytest`` directly on our package files may not work because Certbot relies on setuptools to register and find its plugins.

3. If you'd like to include automated renewal in your package ``certbot renew -q`` should be added to crontab or systemd timer. Additionally you should include a random per-machine time offset to avoid having a large number of your clients hit Let's Encrypt's servers simultaneously.

4. ``jws`` is an internal script for ``acme`` module and it doesn't have to be packaged - it's mostly for debugging: you can use it as ``echo foo | jws sign | jws verify``.

5. Do get in touch with us. We are happy to make any changes that will make packaging easier. If you need to apply some patches don't do it downstream - make a PR here.
