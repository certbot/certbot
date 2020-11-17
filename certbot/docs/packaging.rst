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

.. _`Semantic Versioning`: https://semver.org/

Our packages are cryptographically signed and their signature can be verified
using the PGP key ``A2CFB51FA275A7286234E7B24D17C995CD9775F2``. This key can be
found on major key servers and at https://dl.eff.org/certbot.pub.

Notes for package maintainers
=============================

0. Please use our tagged releases, not ``master``!

1. Do not package ``certbot-compatibility-test`` as it's only used internally.

2. To run tests on our packages, you should use pytest by running the command ``python -m pytest``. Running ``pytest`` directly may not work because PYTHONPATH is not handled the same way and local modules may not be found by the test runner.

3. If you'd like to include automated renewal in your package:

  - ``certbot renew -q`` should be added to crontab or systemd timer.
  - A random per-machine time offset should be included to avoid having a large number of your clients hit Let's Encrypt's servers simultaneously.
  - ``--preconfigured-renewal`` should be included on the CLI or in ``cli.ini`` for all invocations of Certbot, so that it can adjust its interactive output regarding automated renewal (Certbot >= 1.9.0).

4. ``jws`` is an internal script for ``acme`` module and it doesn't have to be packaged - it's mostly for debugging: you can use it as ``echo foo | jws sign | jws verify``.

5. Do get in touch with us. We are happy to make any changes that will make packaging easier. If you need to apply some patches don't do it downstream - make a PR here.
