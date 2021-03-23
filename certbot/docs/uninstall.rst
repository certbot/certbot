=========================
Uninstalling certbot-auto
=========================

To uninstall ``certbot-auto``, you need to do three things:

1. If you added a cron job or systemd timer to automatically run
   ``certbot-auto`` to renew your certificates, you should delete it. If you
   did this by following our instructions, you can delete the entry added to
   ``/etc/crontab`` by running a command like ``sudo sed -i '/certbot-auto/d'
   /etc/crontab``.
2. Delete the ``certbot-auto`` script. If you placed it in ``/usr/local/bin``
   like we recommended, you can delete it by running ``sudo rm
   /usr/local/bin/certbot-auto``.
3. Delete the Certbot installation created by ``certbot-auto`` by running
   ``sudo rm -rf /opt/eff.org``.
