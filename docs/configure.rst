onfiguration Files
=====================

.. contents:: Table of Contents
   :local:

This is another new section that will talk about what can be configured and will explain the interaction between the renewal configuration file and the global configuration file. The text about the global configuration file has been moved here from using.rst

.. _renewal-config-file:


Renewal Configuration File

Modifying the Renewal Configuration File
----------------------------------------

When a certificate is issued, by default Certbot creates a renewal configuration file that
tracks the options that were selected when Certbot was run. This allows Certbot
to use those same options again when it comes time for renewal. These renewal
configuration files are located at ``/etc/letsencrypt/renewal/CERTNAME``.

For advanced certificate management tasks, it is possible to manually modify the certificate's
renewal configuration file, but this is discouraged since it can easily break Certbot's
ability to renew your certificates. If you choose to modify the renewal configuration file
we advise you to test its validity with the ``certbot renew --dry-run`` command.

.. warning:: Modifying any files in ``/etc/letsencrypt`` can damage them so Certbot can no longer properly manage its certificates, and we do not recommend doing so.

For most tasks, it is safest to limit yourself to pointing symlinks at the files there, or using
``--deploy-hook`` to copy / make new files based upon those files, if your operational situation requires it
(for instance, combining certificates and keys in different way, or having copies of things with different
specific permissions that are demanded by other programs).

If the contents of ``/etc/letsencrypt/archive/CERTNAME`` are moved to a new folder, first specify
the new folder's name in the renewal configuration file, then run ``certbot update_symlinks`` to
point the symlinks in ``/etc/letsencrypt/live/CERTNAME`` to the new folder.

If you would like the live certificate files whose symlink location Certbot updates on each run to
reside in a different location, first move them to that location, then specify the full path of
each of the four files in the renewal configuration file. Since the symlinks are relative links,
you must follow this with an invocation of ``certbot update_symlinks``.

For example, say that a certificate's renewal configuration file previously contained the following
directives::

  archive_dir = /etc/letsencrypt/archive/example.com
  cert = /etc/letsencrypt/live/example.com/cert.pem
  privkey = /etc/letsencrypt/live/example.com/privkey.pem
  chain = /etc/letsencrypt/live/example.com/chain.pem
  fullchain = /etc/letsencrypt/live/example.com/fullchain.pem

The following commands could be used to specify where these files are located::

  mv /etc/letsencrypt/archive/example.com /home/user/me/certbot/example_archive
  sed -i 's,/etc/letsencrypt/archive/example.com,/home/user/me/certbot/example_archive,' /etc/letsencrypt/renewal/example.com.conf
  mv /etc/letsencrypt/live/example.com/*.pem /home/user/me/certbot/
  sed -i 's,/etc/letsencrypt/live/example.com,/home/user/me/certbot,g' /etc/letsencrypt/renewal/example.com.conf
  certbot update_symlinks





.. _config-file:

Global Configuration File
=========================

Certbot accepts a global configuration file that applies its options to all invocations
of Certbot. Certificate specific configuration choices should be set in the ``.conf``
files that can be found in ``/etc/letsencrypt/renewal``.

By default no cli.ini file is created, after creating one 
it is possible to specify the location of this configuration file with
``certbot-auto --config cli.ini`` (or shorter ``-c cli.ini``). An
example configuration file is shown below:

.. include:: ../examples/cli.ini
   :code: ini

By default, the following locations are searched:

- ``/etc/letsencrypt/cli.ini``
- ``$XDG_CONFIG_HOME/letsencrypt/cli.ini`` (or
  ``~/.config/letsencrypt/cli.ini`` if ``$XDG_CONFIG_HOME`` is not
  set).

Since this configuration file applies to all invocations of certbot it is incorrect
to list domains in it. Listing domains in cli.ini may prevent renewal from working.
Additionally due to how arguments in cli.ini are parsed, options which wish to
not be set should not be listed. Options set to false will instead be read
as being set to true by older versions of Certbot, since they have been listed
in the config file.

.. keep it up to date with constants.py

