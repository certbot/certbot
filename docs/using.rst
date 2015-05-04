==============================
Using the Let's Encrypt client
==============================

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

For squezze you will need to:

- Use ``virtualenv --no-site-packages -p python`` instead of ``-p python2``.


.. _`#280`: https://github.com/letsencrypt/lets-encrypt-preview/issues/280


Mac OSX
-------

.. code-block:: shell

   sudo ./bootstrap/mac.sh


Quick Usage
===========
Using docker you can quickly get yourself a testing cert.  From the server that the domain your requesting a cert for resolves to, download docker 1.5, and issue the following command:

::

    docker run -it --rm -p 443:443 -v $PWD/certs/:/etc/letsencrypt/certs/ letsencrypt/lets-encrypt-preview

And follow the instructions.  Your new cert will be available in `certs/`

Installation
============

.. code-block:: shell

   virtualenv --no-site-packages -p python2 venv
   ./venv/bin/python setup.py install
   sudo ./venv/bin/letsencrypt


Usage
=====

The letsencrypt commandline tool has a builtin help:

.. code-block:: shell

   ./venv/bin/letsencrypt --help


.. _augeas: http://augeas.net/
.. _m2crypto: https://github.com/M2Crypto/M2Crypto
.. _swig: http://www.swig.org/
