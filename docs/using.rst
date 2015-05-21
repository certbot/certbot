==============================
Using the Let's Encrypt client
==============================

Quick start
===========

Using docker you can quickly get yourself a testing cert. From the
server that the domain your requesting a cert for resolves to,
download docker, and issue the following command

.. code-block:: shell

   sudo docker run -it --rm -p 443:443 --name letsencrypt \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               quay.io/letsencrypt/lets-encrypt-preview:latest

And follow the instructions. Your new cert will be available in
``/etc/letsencrypt/certs``.


Prerequisites
=============

The demo code is supported and known to work on **Ubuntu and
Debian**. Therefore, prerequisites for other platforms listed below
are provided mainly for the :ref:`developers <hacking>` reference.

In general:

* ``sudo`` is required as a suggested way of running privileged process
* `swig`_ is required for compiling `m2crypto`_
* `augeas`_ is required for the ``python-augeas`` bindings


Ubuntu
------

.. code-block:: shell

   sudo ./bootstrap/ubuntu.sh


Debian
------

.. code-block:: shell

   sudo ./bootstrap/debian.sh

For squeeze you will need to:

- Use ``virtualenv --no-site-packages -p python`` instead of ``-p python2``.


.. _`#280`: https://github.com/letsencrypt/lets-encrypt-preview/issues/280


Mac OSX
-------

.. code-block:: shell

   sudo ./bootstrap/mac.sh


Installation
============

.. code-block:: shell

   virtualenv --no-site-packages -p python2 venv
   ./venv/bin/pip install -r requirements.txt


Usage
=====

The letsencrypt commandline tool has a builtin help:

.. code-block:: shell

   ./venv/bin/letsencrypt --help


.. _augeas: http://augeas.net/
.. _m2crypto: https://github.com/M2Crypto/M2Crypto
.. _swig: http://www.swig.org/
