==========================
Postfix plugin for Certbot
==========================

Note: this MTA installer is in **developer beta**-- we appreciate any testing, feedback, or
feature requests for this plugin.

To install this plugin, in the root of this repo, run::

    python tools/venv.py
    source venv/bin/activate

You can use this installer with any `authenticator plugin
<https://certbot.eff.org/docs/using.html#getting-certificates-and-choosing-plugins>`_.
For instance, with the `standalone authenticator
<https://certbot.eff.org/docs/using.html#standalone>`_, which requires no extra server
software, you might run::

    sudo ./venv/bin/certbot run --standalone -i postfix -d <domain name>

To just install existing certs with this plugin, run::

    sudo ./venv/bin/certbot install -i postfix --cert-path <path to cert> --key-path <path to key> -d <domain name>
