This is the Let's Encrypt Agent DEVELOPER PREVIEW repository.

DO NOT RUN THIS CODE ON A PRODUCTION WEBSERVER.  IT WILL INSTALL CERTIFICATES
SIGNED BY A TEST CA, AND WILL CAUSE CERT WARNINGS FOR USERS.

This code intended for testing, demonstration, and integration engineering
with OSes and hosting platforms.  Currently the code works with Linux and
Apache, though we will be expanding it to other platforms.

# Running the demo on Debian

`
sudo apt-get install python-pip python-crypto python-dev python-jsonschema
python-augeas gcc python-m2crypto 

sudo pip install jose
`

Now get a working copy of the python2 "dialog" module.  On debian stable:

`sudo apt-get install python-dialog`

on testing/unstable, "pip uninstall dialog", "pip uninstall pythondialog",then...

`
sudo pip install pythondialog=2.7 

sudo ./letsencrypt.py
`

Debian packaging work will continue in the separate "debian" branch of this
repo.
