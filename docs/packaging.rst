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

Already ongoing efforts
=======================


Arch
----

From our official releases:

- https://www.archlinux.org/packages/community/any/python-acme
- https://www.archlinux.org/packages/community/any/certbot
- https://www.archlinux.org/packages/community/any/certbot-apache
- https://www.archlinux.org/packages/community/any/certbot-nginx
- https://www.archlinux.org/packages/community/any/certbot-dns-cloudflare
- https://www.archlinux.org/packages/community/any/certbot-dns-cloudxns
- https://www.archlinux.org/packages/community/any/certbot-dns-digitalocean
- https://www.archlinux.org/packages/community/any/certbot-dns-dnsimple
- https://www.archlinux.org/packages/community/any/certbot-dns-dnsmadeeasy
- https://www.archlinux.org/packages/community/any/certbot-dns-google
- https://www.archlinux.org/packages/community/any/certbot-dns-luadns
- https://www.archlinux.org/packages/community/any/certbot-dns-nsone
- https://www.archlinux.org/packages/community/any/certbot-dns-rfc2136
- https://www.archlinux.org/packages/community/any/certbot-dns-route53

From ``master``: https://aur.archlinux.org/packages/certbot-git

Debian (and its derivatives, including Ubuntu)
----------------------------------------------

- https://packages.debian.org/sid/certbot
- https://packages.debian.org/sid/python-certbot
- https://packages.debian.org/sid/python-certbot-apache

Fedora
------

In Fedora 23+.

- https://apps.fedoraproject.org/packages/python-acme
- https://apps.fedoraproject.org/packages/certbot
- https://apps.fedoraproject.org/packages/python-certbot-apache
- https://apps.fedoraproject.org/packages/python-certbot-dns-cloudflare
- https://apps.fedoraproject.org/packages/python-certbot-dns-cloudxns
- https://apps.fedoraproject.org/packages/python-certbot-dns-digitalocean
- https://apps.fedoraproject.org/packages/python-certbot-dns-dnsimple
- https://apps.fedoraproject.org/packages/python-certbot-dns-dnsmadeeasy
- https://apps.fedoraproject.org/packages/python-certbot-dns-google
- https://apps.fedoraproject.org/packages/python-certbot-dns-luadns
- https://apps.fedoraproject.org/packages/python-certbot-dns-nsone
- https://apps.fedoraproject.org/packages/python-certbot-dns-rfc2136
- https://apps.fedoraproject.org/packages/python-certbot-dns-route53
- https://apps.fedoraproject.org/packages/python-certbot-nginx

FreeBSD
-------

- https://www.freshports.org/security/py-acme/
- https://www.freshports.org/security/py-certbot/

Gentoo
------

Currently, all ``certbot`` related packages are in the testing branch:

- https://packages.gentoo.org/packages/app-crypt/certbot
- https://packages.gentoo.org/packages/app-crypt/certbot-apache
- https://packages.gentoo.org/packages/app-crypt/certbot-nginx
- https://packages.gentoo.org/packages/app-crypt/acme

GNU Guix
--------

- https://www.gnu.org/software/guix/package-list.html#certbot

OpenBSD
-------

- http://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/security/letsencrypt/client/
