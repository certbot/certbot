# A New Way to Install Certbot on Linux

Today we released Certbot packaged as a snap, offering a new way to install the client. Most modern Linux distributions (basically any that use systemd) can use the Certbot snap. Some of the benefits of installing Certbot this way are:

* Certbot automatically stays up-to-date, giving you access to the latest features including updates to the TLS configuration Certbot uses when installing certificates with Apache and Nginx.
* Automatic renewal comes preconfigured, so there is no need to manually set up a cron job or systemd timer.
* While not initially available, we're planning to release snaps for all of our DNS plugins as well as instructions for people to create their own 3rd party plugin snaps in the coming months.

Support for Certbot packaged as a snap is currently in its beta phase and only supports the x86_64 architecture, but if you'd like to help us test it, you can find instructions for installing the Certbot snap at
https://certbot.eff.org/instructions by selecting your server software and then choosing "snapd" in the "System" dropdown menu.
