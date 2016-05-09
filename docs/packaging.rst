===============
Packaging Guide
===============

Releases
========

We release packages and upload them to PyPI (wheels and source tarballs).

- https://pypi.python.org/pypi/acme
- https://pypi.python.org/pypi/letsencrypt
- https://pypi.python.org/pypi/letsencrypt-apache
- https://pypi.python.org/pypi/letsencrypt-nginx
- https://pypi.python.org/pypi/letshelp-letsencrypt

The following scripts are used in the process:

- https://github.com/letsencrypt/letsencrypt/blob/master/tools/release.sh
- https://gist.github.com/kuba/b9a3a2ca3bd35b8368ef

We currently version as ``0.0.0.devYYYYMMDD``, and will change at GA time to the following scheme:

- ``0.1.0``
- ``0.2.0dev`` for developement in ``master``
- ``0.2.0`` (only temporarily in ``master``)
- ...

Tracking issue for non-dev release scripts: https://github.com/letsencrypt/letsencrypt/issues/1185

Notes for package maintainers
=============================

0. Please use our releases, not ``master``!

1. Do not package ``letsencrypt-compatibility-test`` - it's only used internally.

2. ``letsencrypt-renewer`` should be added to crontab... but it currently doesn't work well

3. ``letsencrypt.client`` provides developer API so it should be possible to ``import letsencrypt.client`` when the package is installed (``letsencrypt`` vs ``python-letsencrypt`` debate for Debian).

4. ``jws`` is an internal script for ``acme`` module and it doesn't have to be packaged - it's mostly for debugging: you can use it as ``echo foo | jws sign | jws verify``.

5. Do get in touch with us. We are happy to make any changes that will make packaging easier. If you need to apply some patches don't do it downstream - make a PR here.

Already ongoing efforts
-----------------------


Arch
====

From PyPI:
- https://www.archlinux.org/packages/community/any/python2-acme
- https://www.archlinux.org/packages/community/any/letsencrypt
- https://www.archlinux.org/packages/community/any/letsencrypt-apache
- https://www.archlinux.org/packages/community/any/letsencrypt-nginx
- https://www.archlinux.org/packages/community/any/letshelp-letsencrypt

From ``master``: https://aur.archlinux.org/packages/letsencrypt-git

Debian (and its derivatives, including Ubuntu)
======

https://alioth.debian.org/projects/letsencrypt/

Fedora
======

In Fedora 23+.

- https://admin.fedoraproject.org/pkgdb/package/letsencrypt/
- https://admin.fedoraproject.org/pkgdb/package/python-acme/
- https://bugzilla.redhat.com/show_bug.cgi?id=1287193 (review request, closed)

FreeBSD
=======

https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=203405

GNU Guix
========

- https://www.gnu.org/software/guix/package-list.html#letsencrypt

OpenBSD
=======

- http://cvsweb.openbsd.org/cgi-bin/cvsweb/ports/security/letsencrypt/
- https://github.com/letsencrypt/letsencrypt/pull/1175
- https://github.com/letsencrypt/letsencrypt/issues/1174
