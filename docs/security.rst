========
Security
========

This part of the documentation is about the letsencrypt client code and:

* ways of using it
* threat models
* how we counter-act the threats

States
------

* REVIEWED means that there has been a security review and it was found safe.
* IMPLEMENTED means it is implemented, supported and considered safe.
* PARTIAL means some stuff has been done on the way, but not fully
  implemented yet
* TODO means that we want to implement it, but it is not there yet.


General notes
=============

This documentation is **only** about the security of the letsencrypt code, not
about any 3rd party code or how to safely configure or use the 3rd party code.

Aside from *security* threats, there is of course always some danger caused by
potential malfunctions of the letsencrypt code (especially when running as
root). This is nothing special for letsencrypt, this applies to every code
executed on your system.

letsencrypt counter-acts potential damage by providing rollback of
configuration changes it does. [IMPLEMENTED]

Also, the system administrator of course must have backups of the system. :)


Use case "root@server/apache2" [IMPLEMENTED]
============================================

A system administrator (root/sudo-ALL user) is invoking letsencrypt on the
command line of the server.

There is no additional security threat introduced by letsencrypt here, because
a local root user could do anything on the system anyway.


Use case "user@client/ddns" [TODO, PR exists]
=============================================

An unprivileged user on some client machine is invoking letsencrypt on the
command line.

This can be supported for DNS-based challenges if the user is capable of
updating DNS with the required challenge to prove domain control.

There is no additional security threat introduced by the letsencrypt code
here as the user is capable of running the required "nsupdate" unprivileged
commandline tool anyway.

