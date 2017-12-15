=====================
Reference
=====================

.. include:: configure.rst


Certbot Logs
==========


.. _log-rotation:

Log Rotation
------------

By default certbot stores status logs in ``/var/log/letsencrypt``. By default
certbot will begin rotating logs once there are 1000 logs in the log directory.
Meaning that once 1000 files are in ``/var/log/letsencrypt`` Certbot will delete
the oldest one to make room for new logs. The number of subsequent logs can be
changed by passing the desired number to the command line flag
``--max-log-backups``.

.. _command-line:

Certbot Command-line Reference
==============================

Certbot supports a lot of command line options. Here's the full list, from
``certbot --help all``:

.. literalinclude:: cli-help.txt



