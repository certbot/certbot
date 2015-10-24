==========
User Guide
==========

.. contents:: Table of Contents
   :local:


Installation
============

Unless you have a very specific requirements, we kindly ask you to use
the letsencrypt-auto_ method described below. It's the fastest, the
most thourougly tested and the most reliable way of getting our
software and the free SSL certificates!

.. letsencrypt-auto:

letsencrypt-auto
----------------

``letsencrypt-auto`` is a wrapper which installs some dependencies
from your OS standard package repostories (e.g using `apt-get` or
`yum`), and for other depencies it sets up a virtualized Python
environment with packages downloaded from PyPI [#venv]_. It also
provides automated updates.

Firstly, please `install Git`_ and run the following commands:

.. code-block:: shell

   git clone https://github.com/letsencrypt/letsencrypt
   cd letsencrypt

.. warning:: Alternatively you could `download the ZIP archive`_ and
   extract the snapshot of our repository, but it's strongly
   recommended to use the above method instead.

.. _`install Git`: https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
.. _`download the ZIP archive`:
   https://github.com/letsencrypt/letsencrypt/archive/master.zip

To install and run the client you just need to type:

.. code-block:: shell

   ./letsencrypt-auto

Throughout the documentation, whenever you see references to
``letsencrypt`` script/binary, you can subsitute in
``letsencrypt-auto``. For example, to get the help you would type:

.. code-block:: shell

  ./letsencrypt-auto --help


Running with Docker
-------------------

Docker_ is another way to quickly obtain testing certs. From the
server that the domain your requesting a cert for resolves to,
`install Docker`_, issue the following command:

.. code-block:: shell

   sudo docker run -it --rm -p 443:443 --name letsencrypt \
               -v "/etc/letsencrypt:/etc/letsencrypt" \
               -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
               quay.io/letsencrypt/letsencrypt:latest auth

and follow the instructions. Your new cert will be available in
``/etc/letsencrypt/certs``.

.. _Docker: https://docker.com
.. _`install Docker`: https://docs.docker.com/userguide/


Distro packages
---------------

Unfortunately, this is an ongoing effort. If you'd like to package
Let's Encrypt client for your distribution of choice please have a
look at :doc:`packaging`.


From source
-----------

Installation from source is only supported for developers and the
whole process is described in :doc:`dev`.

.. warning:: Please do **not** use ``python setup.py install`` or
   ``python pip install .``. Please do **not** attempt the
   installation commands as superuser/root and/or without virtual
   environment, e.g. ``sudo python setup.py install``, ``sudo pip
   install``, ``sudo ./venv/bin/...``. These modes of operation might
   corrupt your operating system and are **not supported** by the
   Let's Encrypt team!


Plugins
=======

Third party plugins are listed at
https://github.com/letsencrypt/letsencrypt/wiki/Plugins. If that
that's not enough, you can always :ref:`write your own plugin
<dev-plugin>`.


Configuration file
==================

It is possible to specify configuration file with
``letsencrypt-auto --config cli.ini`` (or shorter ``-c cli.ini``). An
example configuration file is shown below:

.. include:: ../examples/cli.ini
   :code: ini

By default, the following locations are searched:

- ``/etc/letsencrypt/cli.ini``
- ``$XDG_CONFIG_HOME/letsencrypt/cli.ini`` (or
  ``~/.config/letsencrypt/cli.ini`` if ``$XDG_CONFIG_HOME`` is not
  set).

.. keep it up to date with constants.py


.. rubric:: Footnotes

.. [#venv] By using this virtualized Python enviroment (`virtualenv
           <https://virtualenv.pypa.io>`_) we don't pollute the main
           OS space with packages from PyPI!
