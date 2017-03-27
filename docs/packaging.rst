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

The following scripts are used in the process:

- https://github.com/letsencrypt/letsencrypt/blob/master/tools/release.sh

We use git tags to identify releases, using `Semantic Versioning`_. For
example: `v0.11.1`.

.. _`Semantic Versioning`: http://semver.org/

Notes for package maintainers
=============================

0. Please use our tagged releases, not ``master``!

1. Do not package ``certbot-compatibility-test`` or ``letshelp-certbot`` - it's only used internally.

2. If you'd like to include automated renewal in your package ``certbot renew -q`` should be added to crontab or systemd timer. Additionally you should include a random per-machine time offset to avoid having a large number of your clients hit Let's Encrypt's servers simultaneously.

3. ``jws`` is an internal script for ``acme`` module and it doesn't have to be packaged - it's mostly for debugging: you can use it as ``echo foo | jws sign | jws verify``.

4. Do get in touch with us. We are happy to make any changes that will make packaging easier. If you need to apply some patches don't do it downstream - make a PR here.

Already ongoing efforts
=======================


Arch
----

From our official releases:

- https://www.archlinux.org/packages/community/any/python2-acme
- https://www.archlinux.org/packages/community/any/certbot
- https://www.archlinux.org/packages/community/any/certbot-apache
- https://www.archlinux.org/packages/community/any/certbot-nginx

From ``master``: https://aur.archlinux.org/packages/certbot-git

Debian (and its derivatives, including Ubuntu)
------

- https://packages.debian.org/sid/certbot
- https://packages.debian.org/sid/python-certbot
- https://packages.debian.org/sid/python-certbot-apache

Fedora
------

In Fedora 23+.

- https://admin.fedoraproject.org/pkgdb/package/certbot/
- https://admin.fedoraproject.org/pkgdb/package/python-acme/

FreeBSD
-------

- https://svnweb.freebsd.org/ports/head/security/py-certbot/

GNU Guix
--------

- https://www.gnu.org/software/guix/package-list.html#certbot

OpenBSD
-------

- http://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/security/letsencrypt/client/
