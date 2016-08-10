=====================
Quick Installation
=====================

If ``certbot`` (or ``letsencrypt``) is packaged for your Unix OS (visit
certbot.eff.org_ to find out), you can install it
from there, and run it by typing ``certbot`` (or ``letsencrypt``).  Because
not all operating systems have packages yet, we provide a temporary solution
via the ``certbot-auto`` wrapper script, which obtains some dependencies from
your OS and puts others in a python virtual environment::

  user@webserver:~$ wget https://dl.eff.org/certbot-auto
  user@webserver:~$ chmod a+x ./certbot-auto
  user@webserver:~$ ./certbot-auto --help

.. hint:: The certbot-auto download is protected by HTTPS, which is pretty good, but if you'd like to
          double check the integrity of the ``certbot-auto`` script, you can use these steps for verification before running it::

            user@server:~$ wget -N https://dl.eff.org/certbot-auto.asc
            user@server:~$ gpg2 --recv-key A2CFB51FA275A7286234E7B24D17C995CD9775F2
            user@server:~$ gpg2 --trusted-key 4D17C995CD9775F2 --verify certbot-auto.asc certbot-auto

And for full command line help, you can type::

  ./certbot-auto --help all

``certbot-auto`` updates to the latest client release automatically.  And
since ``certbot-auto`` is a wrapper to ``certbot``, it accepts exactly
the same command line flags and arguments.  More details about this script and
other installation methods can be found `in the User Guide
<https://certbot.eff.org/docs/using.html#installation>`_.

.. _certbot.eff.org: https://certbot.eff.org/
