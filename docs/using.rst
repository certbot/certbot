==============================
Using the Let's Encrypt client
==============================

Prerequisites
=============

The demo code is supported and known to work on **Ubuntu only** (even
closely related `Debian is known to fail`_).

Therefore, prerequisites for other platforms listed below are provided
mainly for the :ref:`developers <hacking>` reference.

In general:

* `swig`_ is required for compiling `m2crypto`_
* `augeas`_ is required for the ``python-augeas`` bindings

.. _Debian is known to fail: https://github.com/letsencrypt/lets-encrypt-preview/issues/68

Ubuntu
------

::

    sudo apt-get install python python-setuptools python-virtualenv python-dev \
                 gcc swig dialog libaugeas0 libssl-dev libffi-dev \
                 ca-certificates

.. Please keep the above command in sync with .travis.yml (before_install)

Mac OSX
-------

::

    sudo brew install augeas swig


Installation
============

::

    virtualenv --no-site-packages -p python2 venv
    ./venv/bin/python setup.py install
    sudo ./venv/bin/letsencrypt


Usage
=====

The letsencrypt commandline tool has a builtin help:

::

   ./venv/bin/letsencrypt --help


.. _augeas: http://augeas.net/
.. _m2crypto: https://github.com/M2Crypto/M2Crypto
.. _swig: http://www.swig.org/
