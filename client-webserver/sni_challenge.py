#!/usr/bin/env python

import subprocess
from Crypto.PublicKey import RSA
from Crypto import Random
import hmac
import hashlib
from shutil import move
from os import remove, close

CHOC_DIR = "/home/james/Documents/apache_choc/"
#CHOC_KEY = "../ca/sni_challenge/testing.key"
CHOC_KEY = CHOC_DIR + "testing.key"
SERVER_BASE = "/etc/apache2/"
CHOC_CERT = CHOC_DIR + "choc.crt"
CSR = CHOC_DIR + "choc.csr"
CHOC_CERT_CONF = "choc_cert_extensions.cnf"
OPTIONS_SSL_CONF = CHOC_DIR + "options-ssl.conf"
APACHE_CHALLENGE_CONF = CHOC_DIR + "choc_sni_cert_challenge.conf"
S_SIZE = 32
NONCE_SIZE = 32

def findApacheConfigFile():
    #This needs to be fixed to account for multiple httpd.conf files
    try:
        p = subprocess.check_output(["sudo", "find", "/", "-name", "httpd.conf"], stderr=open("/dev/null"))
	p = p[:len(p)-1]
	print "Apache Config: ", p
	return p
    except subprocess.CalledProcessError, e:
        print "httpd.conf not found"
	print "Please include .... in the conf file"
        return None

def modifyApacheConfig(mainConfig, nonce, ip_addr):
    configText = "<IfModule mod_ssl.c> \n \
<VirtualHost " + ip_addr + ":443> \n \
Servername " + nonce + ".chocolate \n \
UseCanonicalName on \n \
\n \
LimitRequestBody 1048576 \n \
\n \
Include " + OPTIONS_SSL_CONF + " \n \
SSLCertificateFile " + CHOC_CERT + " \n \
SSLCertificateKeyFile " + CHOC_KEY + " \n \
\n \
DocumentRoot " + CHOC_DIR + "challenge_page/ \n \
</VirtualHost> \n \
</IfModule>"

    checkForApacheConfInclude(mainConfig)
    newConf = open(APACHE_CHALLENGE_CONF, 'w')
    newConf.write(configText)
    newConf.close()

# Need to add NameVirtualHost IP_ADDR
def checkForApacheConfInclude(mainConfig):
    searchStr = "Include " + APACHE_CHALLENGE_CONF
    #conf = open(mainConfig, 'r+')
    conf = open(mainConfig, 'r')
    flag = False
    for line in conf:
        if line.startswith(searchStr):
            flag = True
            break
    if not flag:
        #conf.write(searchStr)
	process = subprocess.Popen(["echo", "\n" + searchStr], stdout=subprocess.PIPE)
        subprocess.check_output(["sudo", "tee", "-a", mainConfig], stdin=process.stdout)
	process.stdout.close()

    conf.close();
        

def createChallengeCert(ext):
    #Assume CSR is already generated from original request
    updateCertConf(ext)
    subprocess.call(["openssl", "x509", "-req", "-days", "21", "-extfile", CHOC_CERT_CONF, "-extensions", "v3_ca", "-signkey", CHOC_KEY, "-out", CHOC_CERT, "-in", CSR])
    

def generateExtension(challengeValue):
    rsaPrivKey = RSA.importKey(open(CHOC_KEY).read())
    r = rsaPrivKey.decrypt(challengeValue)
    print r

    s = Random.get_random_bytes(S_SIZE)
    #s = "0xDEADBEEF"
    extHMAC = hmac.new(r, str(s), hashlib.sha256)
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
    subprocess.call(["sudo", "/etc/init.d/apache2", "reload"])

#main call
def perform_sni_cert_challenge(address, r, nonce):
    ext = generateExtension(r)
    createChallengeCert(ext)
    
    #Need to decide the form of nonce
    modifyApacheConfig(findApacheConfigFile(), nonce, address)
    apache_restart()

def main():

    testkey = RSA.importKey(open(CHOC_KEY).read())

    #the second parameter is ignored
    #https://www.dlitz.net/software/pycrypto/api/current/

    r = Random.get_random_bytes(S_SIZE)
    r = "testValueForR"
    nonce = Random.get_random_bytes(NONCE_SIZE)
    nonce = "nonce"

    y = testkey.encrypt(r, 0)
    perform_sni_cert_challenge("127.0.0.1", y, nonce)

if __name__ == "__main__":
    main()
