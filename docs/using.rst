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

Ubuntu - Tested on 14.10 LTS x64 and 14.04.1 LTS x64 (using pip)
------

::
  
    sudo apt-get -y update
    sudo apt-get -y install python python-pip python-setuptools python-virtualenv python-dev \
                            gcc swig dialog libaugeas0 libssl-dev libffi-dev ca-certificates git
    git clone https://github.com/letsencrypt/lets-encrypt-preview.git ~/lets-encrypt-preview
    sudo pip install -e ~/lets-encrypt-preview
    letsencrypt -d `hostname`

.. Please keep the above command in sync with .travis.yml (before_install)

Debian - Tested on 7.0 x64 (Wheezy) and 6.0 x64 (Squeeze[1]) (using pip)
------

::
  
    sudo apt-get -y update [2]_.
    sudo apt-get -y install python python-pip python-setuptools python-virtualenv python-dev dpkg-dev\
                            gcc swig dialog libaugeas0 libssl-dev libffi-dev ca-certificates git
    git clone https://github.com/letsencrypt/lets-encrypt-preview.git ~/lets-encrypt-preview
    sudo pip install -e ~/lets-encrypt-preview
    letsencrypt -d `hostname`
    
.. [1] Dialog problems prevent Squeeze installs from working without the use of pip currently.
.. [2] Squeeze may not come setup for simple sudo use.  You mau have `set up sudo`_ before starting.
.. _set up sudo: https://wiki.debian.org/sudo
.. Please keep the above command in sync with .travis.yml (before_install)


Mac OSX
-------

::

    sudo brew install augeas swig


Installation Using VirtualEnv
=============================

VirtualEnv allows significant development advantages.  Pay attention to the directions below.

Ubuntu - 14.10 x64
------

::
  
    sudo apt-get -y update
    sudo apt-get -y install python python-setuptools python-virtualenv python-dev gcc git \
                             swig dialog libaugeas0 libssl-dev libffi-dev ca-certificates dpkg-dev
    git clone https://github.com/letsencrypt/lets-encrypt-preview.git ~/lets-encrypt-preview
    cd ~/lets-encrypt-preview; virtualenv -p python venv && source venv/bin/activate
    python setup.py install
    letsencrypt -d `hostname`

Ubuntu - 14.04.1 LTS x64
------

::

    sudo apt-get -y update
    sudo apt-get -y install python python-setuptools python-virtualenv python-dev gcc git \
                             swig dialog libaugeas0 libssl-dev libffi-dev ca-certificates dpkg-dev
    git clone https://github.com/letsencrypt/lets-encrypt-preview.git ~/lets-encrypt-preview
    cd ~/lets-encrypt-preview; virtualenv -p python venv && source venv/bin/activate
    python setup.py install
    letsencrypt -d `hostname`

Debian - 7.0 Wheezy x64
------

::

    sudo apt-get -y update
    sudo apt-get -y install python python-setuptools python-virtualenv python-dev gcc git \
                             swig dialog libaugeas0 libssl-dev libffi-dev ca-certificates dpkg-dev
    git clone https://github.com/letsencrypt/lets-encrypt-preview.git ~/lets-encrypt-preview
    cd ~/lets-encrypt-preview; virtualenv -p python venv && source venv/bin/activate
    python setup.py install
    letsencrypt -d `hostname`


Usage
=====

The letsencrypt commandline tool has a builtin help:

::

   ./venv/bin/letsencrypt --help


.. _augeas: http://augeas.net/
.. _m2crypto: https://github.com/M2Crypto/M2Crypto
.. _swig: http://www.swig.org/
