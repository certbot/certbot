This is the Let's Encrypt Agent DEVELOPER PREVIEW repository.

DO NOT RUN THIS CODE ON A PRODUCTION WEBSERVER.  IT WILL INSTALL CERTIFICATES SIGNED BY A TEST CA, AND WILL CAUSE CERT WARNINGS FOR USERS.

This code intended for testing, demonstration, and integration engineering
with OSes and hosting platforms.  Currently the code works with Linux and
Apache, though we will be expanding it to other platforms.

## Running the demo code on Ubuntu 

`sudo apt-get install python-pip python-crypto python-dev python-jsonschema python-augeas gcc python-m2crypto python-dialog` 

`sudo pip install jose`

`sudo ./letsencrypt.py`

Hint: on Debian testing/unstable, python-dialog is unavailable and you may
need to do `sudo pip install python2-pythondialog` (lets-encrypt does not yet
handle debian unstable's Apache2 conf layout, either...)

## Running the demo code on FreeBSD

```
# clone repository
git clone https://github.com/letsencrypt/lets-encrypt-preview.git; cd lets-encrypt-preview

# install python dependencies and symlink 'swig'
sudo pkg install -y py27-pip augeas swig ; sudo ln -s /usr/local/bin/swig2.0 /usr/local/bin/swig

# depending on your shell
rehash

# install letsencrypt dependencies
sudo pip install -r requirements.txt
sudo ./letsencrypt.py
```
Note: letsencrypt.py displays window but it doesn't currently work because of issues related to paths, missing commands etc. but it will help to fast start with development under BSD system.

## Command line usage

```
sudo ./letsencrypt.py  (default authentication mode using pythondialog) options 

--text (text mode)                              
--privkey= (specify privatekey file to use to generate the certificate)            
--csr= (Use a specific CSR. If this is specified, privkey must also be specified with the correct private key for the CSR)                             
--server (list the ACME CA server address)
--revoke (revoke a certificate)
--view-checkpoints (Used to view available checkpoints and see what configuration changes have been made)
--rollback=X (Revert the configuration X number of checkpoints)                    
--redirect (Automatically redirect all HTTP traffic to HTTPS for the newly authenticated vhost)                   
--no-redirect (Skip the HTTPS redirect question, allowing both HTTP and HTTPS)
--agree-eula (Skip the end user agreement screen)
```
