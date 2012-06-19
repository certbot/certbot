import subprocess
from Crypto.PublicKey import RSA
import hmac
import hashlib
import random
from shutil import move
from os import remove, close

CHOC_DIR = "/home/james/Documents/apache_choc/"
CHOC_KEY = CHOC_DIR + "testing.key"
SERVER_BASE = "/etc/apache2/"
CHOC_CSR = CHOC_DIR + "choc.csr"
CHOC_CERT = CHOC_DIR + "choc.crt"
CSR = CHOC_DIR + "choc.csr"
CHOC_CERT_CONF = CHOC_DIR + "choc_cert2.cnf"
APACHE_CHALLENGE_CONF = CHOC_DIR + "choc_sni_cert_challenge.conf"
S_SIZE = 20

def findApacheConfigFile():
    return CHOC_DIR + "demo_apache.conf"
    try:
        p = subprocess.check_output(['find', '/', '-name', '"httpd.conf"'], stderr=open("/dev/null"))
    except subprocess.CalledProcessError, e:
        print "Not found"

def modifyApacheConfig(mainConfig, nonce, servername):
    configText = "<IfModule mod_ssl.c> \n \
<VirtualHost " + nonce + "-choc." + servername + ":443> \n \
UseCanonicalName on \n \
\n \
LimitRequestBody 1048576 \n \
\n \
Include options-ssl.conf \n \
SSLCertificateFile " + CHOC_CERT + " \n \
SSLCertificateKeyFile " + CHOC_KEY + " \n \
SSLCertificateChainFile /etc/apache2/ssl/sub.class1.server.ca.pem \n \
\n \
DocumentRoot " + CHOC_DIR + "virtual_server/ \n \
</VirtualHost> \n \
</IfModule>"

    checkForApacheConfInclude(mainConfig)
    newConf = open(APACHE_CHALLENGE_CONF, 'w')
    newConf.write(configText)
    newConf.close()

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
    subprocess.call(["openssl", "x509", "-req", "-days", "21", "-extfile", CHOC_CERT_CONF, "-extensions", "v3_ca", "-signkey", CHOC_KEY, "-out", CHOC_CERT, "-in", CHOC_CSR])
    

def generateExtension(challengeValue):
    rsaPrivKey = RSA.importKey(open(CHOC_KEY).read())
    sharedSecret = rsaPrivKey.decrypt(challengeValue)
    print sharedSecret

    s = randomBytes(S_SIZE)
    s = "TALL"
    extHMAC = hmac.new(sharedSecret, s, hashlib.sha256)
    return s + byteToHex(extHMAC.digest())

#Need to look into how this random is generated
def randomBytes(size):
    return "".join(chr(random.randrange(0,256)) for i in xrange(size))

def byteToHex(byteStr):
    return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

def updateCertConf(value):
    confOld = open(CHOC_CERT_CONF)
    confNew = open(CHOC_DIR + 'choc_cert3.cnf', 'w')

    for line in confOld:
        if line.startswith("1.3.3.7=DER:"):
            confNew.write("1.3.3.7=DER:" + value + "\n")
        else:
            confNew.write(line)
    confNew.close()
    confOld.close()
    remove(CHOC_CERT_CONF)
    move(CHOC_DIR + 'choc_cert3.cnf', CHOC_CERT_CONF)

def perform_sni_cert_challenge(encryptedValue):
    ext = generateExtension(encryptedValue)
    createChallengeCert(ext)
    modifyApacheConfig(findApacheConfigFile(), "Nonce", "TestServerName")

def main():
    testkey = RSA.importKey(open(CHOC_KEY).read())

    #the second parameter is ignored
    #https://www.dlitz.net/software/pycrypto/api/current/
    encryptedValue = testkey.encrypt('0x12345678', 0)
    perform_sni_cert_challenge(encryptedValue)

if __name__ == "__main__":
    main()
