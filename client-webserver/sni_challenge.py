#!/usr/bin/env python

import subprocess
from Crypto.PublicKey import RSA
from Crypto import Random
import hmac
import hashlib
from shutil import move
from os import remove, close
import binascii

CHOC_DIR = "/home/james/Documents/apache_choc/"
CHOC_CERT_CONF = "choc_cert_extensions.cnf"
OPTIONS_SSL_CONF = CHOC_DIR + "options-ssl.conf"
APACHE_CHALLENGE_CONF = CHOC_DIR + "choc_sni_cert_challenge.conf"
S_SIZE = 32
NONCE_SIZE = 32

#class sni_challenge(object):
#    def __init__(self, ip_addrs, y, nonce):
#        self.address = ip_addrs

def getChocCertFile(nonce):
    return CHOC_DIR + nonce + ".crt"

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

def getConfigText(nonce, ip_addr, key):
    configText = "<VirtualHost " + ip_addr + ":443> \n \
Servername " + nonce + ".chocolate \n \
UseCanonicalName on \n \
SSLStrictSNIVHostCheck on \n \
\n \
LimitRequestBody 1048576 \n \
\n \
Include " + OPTIONS_SSL_CONF + " \n \
SSLCertificateFile " + getChocCertFile(nonce) + " \n \
SSLCertificateKeyFile " + key + " \n \
\n \
DocumentRoot " + CHOC_DIR + "challenge_page/ \n \
</VirtualHost> \n\n "

    return configText

def modifyApacheConfig(mainConfig, listSNITuple):
    configText = "<IfModule mod_ssl.c> \n"
    for tup in listSNITuple:
        configText += getConfigText(tup[2], tup[0], tup[5])
    configText += "</IfModule> \n"

    checkForApacheConfInclude(mainConfig)
    newConf = open(APACHE_CHALLENGE_CONF, 'w')
    newConf.write(configText)
    newConf.close()

# Need to add NameVirtualHost IP_ADDR or does the chocolate install do this?
def checkForApacheConfInclude(mainConfig):
    searchStr = "Include " + APACHE_CHALLENGE_CONF
    #conf = open(mainConfig, 'r+')
    conf = open(mainConfig, 'r')
    if not any(line.startswith(searchStr) for line in conf):
        #conf.write(searchStr)
	process = subprocess.Popen(["echo", "\n" + searchStr], stdout=subprocess.PIPE)
        subprocess.check_output(["sudo", "tee", "-a", mainConfig], stdin=process.stdout)
	process.stdout.close()

    conf.close()
        

def createChallengeCert(oid, ext, nonce, csr, key):
    #Assume CSR is already generated from original request
    updateCertConf(oid, ext)
    subprocess.call(["openssl", "x509", "-req", "-days", "21", "-extfile", CHOC_CERT_CONF, "-extensions", "v3_ca", "-signkey", key, "-out", getChocCertFile(nonce), "-in", csr])
    

def generateExtension(key, y):
    rsaPrivKey = RSA.importKey(open(key).read())
    r = rsaPrivKey.decrypt(y)
    #print r

    s = Random.get_random_bytes(S_SIZE)
    #s = "0xDEADBEEF"
    extHMAC = hmac.new(r, str(s), hashlib.sha256)
    return byteToHex(s) + extHMAC.hexdigest()

def byteToHex(byteStr):
    return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

#Searches for the first extension specified in binary
def updateCertConf(oid, value):
    """
    Updates the sni_challenge openssl certificate config file

    oid:    string - ex. 1.3.3.7 
    value   string hex - value of OID

    result: updated certificate config file
    """
    confOld = open(CHOC_CERT_CONF)
    confNew = open(CHOC_CERT_CONF + ".tmp", 'w')

    for line in confOld:
        if "=critical, DER:" in line:
            confNew.write(oid + "=critical, DER:" + value + "\n")
        else:
            confNew.write(line)
    confNew.close()
    confOld.close()
    remove(CHOC_CERT_CONF)
    move(CHOC_CERT_CONF + ".tmp", CHOC_CERT_CONF)

def apache_restart():
    subprocess.call(["sudo", "/etc/init.d/apache2", "reload"])

#main call
# address, y, nonce, ext, CSR, KEY
def perform_sni_cert_challenge(listSNITuple):
    for tup in listSNITuple:
        ext = generateExtension(tup[5], tup[1])
        createChallengeCert(tup[3], ext, tup[2], tup[4], tup[5])
    
    modifyApacheConfig(findApacheConfigFile(), listSNITuple)
    apache_restart()

def main():
    key = CHOC_DIR + "testing.key"
    key2 = CHOC_DIR + "testing2.key"
    csr = CHOC_DIR + "choc.csr"
    csr2 = CHOC_DIR + "choc2.csr"

    testkey = RSA.importKey(open(key).read())
    testkey2 = RSA.importKey(open(key2).read())

    r = Random.get_random_bytes(S_SIZE)
    r = "testValueForR"
    nonce = Random.get_random_bytes(NONCE_SIZE)
    nonce = "nonce"
    r2 = "testValueForR2"
    nonce2 = "nonce2"

    #the second parameter is ignored
    #https://www.dlitz.net/software/pycrypto/api/current/
    y = testkey.encrypt(r, 0)
    y2 = testkey2.encrypt(r2, 0)

    nonce = binascii.hexlify(nonce)
    nonce2 = binascii.hexlify(nonce2)

    perform_sni_cert_challenge([("127.0.0.1", y, nonce, "1.3.3.7", csr, key), ("localhost",y2, nonce2, "1.3.3.7", csr2, key2)])

if __name__ == "__main__":
    main()
