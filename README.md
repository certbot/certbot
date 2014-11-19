This is the Let's Encrypt Agent DEVELOPER PREVIEW repository.

DO NOT RUN THIS CODE ON A PRODUCTION WEBSERVER.  IT WILL INSTALL CERTIFICATES SIGNED BY A TEST CA, AND WILL CAUSE CERT WARNINGS FOR USERS.

This code intended for testing, demonstration, and integration engineering
with OSes and hosting platforms.  Currently the code works with Linux and
Apache, though we will be expanding it to other platforms.

## Running the demo code on Ubuntu 

`sudo apt-get install python python-setuptools python-dev python-augeas gcc`

`python setup.py install --user`

`sudo ./letsencrypt.py` (or `~/.local/bin/letsencrypt`)

Note, that letsencrypt does not yet handle Debian unstable's Apache2
conf layout.

## Developing

`python setup.py develop --user`


## Command line usage

sudo ./letsencrypt.py  (default authentication mode using pythondialog)
                                                   
options --text (text mode)                              
--privkey= (specify privatekey file to use to generate the certificate)            
--csr= (Use a specific CSR. If this is specified, privkey must also be             
specified with the correct private key for the CSR)                                
--server (list the ACME CA server address)                       
--revoke (revoke a certificate)                                                    
--view-checkpoints (Used to view available checkpoints and see what                
configuration changes have been made)                                              
--rollback=X (Revert the configuration X number of checkpoints)                    
--redirect (Automatically redirect all HTTP traffic to HTTPS for the newly         
authenticated vhost)                                                               
--no-redirect (Skip the HTTPS redirect question, allowing both HTTP and            
HTTPS)                                                                             
--agree-eula (Skip the end user agreement screen)
