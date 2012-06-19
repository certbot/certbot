#!/usr/bin/env python

import subprocess
from Crypto.PublicKey import RSA
from Crypto import Random
import hmac
import hashlib
import random
from shutil import move
from os import remove, close

CHOC_DIR = "/home/james/Documents/apache_choc/"
CHOC_KEY = CHOC_DIR + "testing.key"
SERVER_BASE = "/etc/apache2/"
CHOC_CERT = CHOC_DIR + "choc.crt"
CSR = CHOC_DIR + "choc.csr"
CHOC_CERT_CONF = CHOC_DIR + "choc_cert_extensions.cnf"
APACHE_CHALLENGE_CONF = CHOC_DIR + "choc_sni_cert_challenge.conf"
S_SIZE = 20

def findApacheConfigFile():
    return CHOC_DIR + "demo_apache.conf"
    try:
        p = subprocess.check_output(['find', '/', '-name', '"httpd.conf"'], stderr=open("/dev/null"))
    except subprocess.CalledProcessError, e:
        print "Not found"

def modifyApacheConfig(mainConfig, nonce, servername, ip_addr):
    configText = "<IfModule mod_ssl.c> \n \
<VirtualHost " + ip_addr + ":443> \n \
Servername " + nonce + "-choc." + servername + " \n \
UseCanonicalName on \n \
\n \
LimitRequestBody 1048576 \n \
\n \
Include options-ssl.conf \n \
SSLCertificateFile " + CHOC_CERT + " \n \
SSLCertificateKeyFile " + CHOC_KEY + " \n \
\n \
DocumentRoot " + CHOC_DIR + "virtual_server/ \n \
</VirtualHost> \n \
</IfModule>"

    checkForApacheConfInclude(mainConfig)
    newConf = open(APACHE_CHALLENGE_CONF, 'w')
    newConf.write(configText)
    newConf.close()

# Need to add NameVirtualHost IP_ADDR
def checkForApacheConfInclude(mainConfig):
    searchStr = "Include " + APACHE_CHALLENGE_CONF
    conf = open(mainConfig, 'r+')
    flag = False
    for line in conf:
        if line.startswith(searchStr):
            flag = True
            break
    if not flag:
        conf.write(searchStr)

    conf.close();
        

def createChallengeCert(ext):
    #Assume CSR is already generated from original request
    updateCertConf(ext)
    subprocess.call(["openssl", "x509", "-req", "-days", "21", "-extfile", CHOC_CERT_CONF, "-extensions", "v3_ca", "-signkey", CHOC_KEY, "-out", CHOC_CERT, "-in", CSR])
    

def generateExtension(challengeValue):
    rsaPrivKey = RSA.importKey(open(CHOC_KEY).read())
    sharedSecret = rsaPrivKey.decrypt(challengeValue)
    print sharedSecret

    s = Random.get_random_bytes(S_SIZE)
    #s = "0xDEADBEEF"
    extHMAC = hmac.new(sharedSecret, str(s), hashlib.sha256)
    return byteToHex(s) + extHMAC.hexdigest()

def byteToHex(byteStr):
    return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

def updateCertConf(value):
    confOld = open(CHOC_CERT_CONF)
    confNew = open(CHOC_CERT_CONF + ".tmp", 'w')

    for line in confOld:
        if line.startswith("1.3.3.7=DER:"):
            confNew.write("1.3.3.7=DER:" + value + "\n")
        else:
            confNew.write(line)
    confNew.close()
    confOld.close()
    remove(CHOC_CERT_CONF)
    move(CHOC_CERT_CONF + ".tmp", CHOC_CERT_CONF)

def apache_restart():
    subprocess.call(["/etc/init.d/apache2", "reload"])

#main call
def perform_sni_cert_challenge(encryptedValue):
    ext = generateExtension(encryptedValue)
    createChallengeCert(ext)
    
    #Need to decide the form of nonce
    modifyApacheConfig(findApacheConfigFile(), "Nonce", "choc_sni_challenge.com", "127.0.0.1")
    #apache_restart()

def main():
    testkey = RSA.importKey(open(CHOC_KEY).read())

    #the second parameter is ignored
    #https://www.dlitz.net/software/pycrypto/api/current/
    encryptedValue = testkey.encrypt('0x12345678', 0)
    perform_sni_cert_challenge(encryptedValue)

if __name__ == "__main__":
    main()
