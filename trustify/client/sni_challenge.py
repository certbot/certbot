#!/usr/bin/env python

import subprocess
import M2Crypto
from Crypto import Random
import hmac
import hashlib
from shutil import move
from os import remove, close, path
import sys
import binascii
import augeas
import jose

from trustify.client import configurator

from trustify.client.CONFIG import CONFIG_DIR, WORK_DIR, SERVER_ROOT
from trustify.client.CONFIG import CHOC_CERT_CONF, OPTIONS_SSL_CONF, APACHE_CHALLENGE_CONF, INVALID_EXT
from trustify.client.CONFIG import S_SIZE, NONCE_SIZE
from trustify.client import logger, crypto_util
from trustify.client.challenge import Challenge

# import configurator

# from CONFIG import CONFIG_DIR, WORK_DIR, SERVER_ROOT
# from CONFIG import CHOC_CERT_CONF, OPTIONS_SSL_CONF, APACHE_CHALLENGE_CONF, INVALID_EXT
# from CONFIG import S_SIZE, NONCE_SIZE
# import logger, trustify_util
# from challenge import Challenge


class SNI_Challenge(Challenge):
    def __init__(self, sni_todos, key_filepath, config):
        '''
        sni_todos:     List of tuples with form (addr, r, nonce)
                       addr (string), r (base64 string), nonce (hex string)
        key:           string - File path to key
        configurator:  Configurator obj
        '''
        self.listSNITuple = sni_todos
        self.key = key_filepath
        self.configurator = config
        self.s = None
        

    def getDvsniCertFile(self, nonce):
        """
        Returns standardized name for challenge certificate

        nonce:  string - hex

        result: returns certificate file name
        """

        return WORK_DIR + nonce + ".crt"

    def findApacheConfigFile(self):
        """
        Locates the file path to the user's main apache config

        result: returns file path if present
        """
        if path.isfile(SERVER_ROOT + "httpd.conf"):
            return SERVER_ROOT + "httpd.conf"
        logger.error("Unable to find httpd.conf, file does not exist in Apache ServerRoot")
        return None

    def __getConfigText(self, nonce, ip_addrs, key):
        """
        Chocolate virtual server configuration text

        nonce:      string - hex
        ip_addr:    string - address of challenged domain
        key:        string - file path to key

        result:     returns virtual host configuration text
        """
        configText = "<VirtualHost " + " ".join(ip_addrs) + "> \n \
ServerName " + nonce + INVALID_EXT + " \n \
UseCanonicalName on \n \
SSLStrictSNIVHostCheck on \n \
\n \
LimitRequestBody 1048576 \n \
\n \
Include " + OPTIONS_SSL_CONF + " \n \
SSLCertificateFile " + self.getDvsniCertFile(nonce) + " \n \
SSLCertificateKeyFile " + key + " \n \
\n \
DocumentRoot " + CONFIG_DIR + "challenge_page/ \n \
</VirtualHost> \n\n "

        return configText

    def modifyApacheConfig(self, mainConfig, listlistAddrs):
        """
        Modifies Apache config files to include the challenge virtual servers

        mainConfig:    string - file path to Apache user config file
        listSNITuple:  list of tuples with form (addr, y, nonce, ext_oid)
                       addr (string), y (byte array), nonce (hex string), ext_oid (string)
        key:           string - file path to key

        result:        Apache config includes virtual servers for issued challenges
        """

        # TODO: Use ip address of existing vhost instead of relying on FQDN
        configText = "<IfModule mod_ssl.c> \n"
        for idx, lis in enumerate(listlistAddrs):
            configText += self.__getConfigText(self.listSNITuple[idx][2], lis, self.key)
        configText += "</IfModule> \n"

        self.checkForApacheConfInclude(mainConfig)
        self.configurator.register_file_creation(True, APACHE_CHALLENGE_CONF)
        newConf = open(APACHE_CHALLENGE_CONF, 'w')
        newConf.write(configText)
        newConf.close()

    def checkForApacheConfInclude(self, mainConfig):
        """
        Adds DVSNI challenge include file if it does not already exist 
        within mainConfig

        mainConfig:  string - file path to main user apache config file

        result:      User Apache configuration includes chocolate sni challenge file
        """
        if len(self.configurator.find_directive(self.configurator.case_i("Include"), APACHE_CHALLENGE_CONF)) == 0:
            #print "Including challenge virtual host(s)"
            self.configurator.add_dir("/files" + mainConfig, "Include", APACHE_CHALLENGE_CONF)

    def createChallengeCert(self, name, ext, nonce, key):
        """
        Modifies challenge certificate configuration and calls openssl binary to create a certificate

        ext:    string - hex z value
        nonce:  string - hex
        key:    string - file path to key

        result: certificate created at getChocCertFile(nonce)
        """
        self.createCHOC_CERT_CONF(name, ext)

        self.configurator.register_file_creation(True, self.getDvsniCertFile(nonce))
        cert_pem = crypto_util.make_ss_cert(key, [nonce + INVALID_EXT, name, ext])
        with open(self.getDvsniCertFile(nonce), 'w') as f:
            f.write(cert_pem)

        #print ["openssl", "x509", "-req", "-days", "21", "-extfile", CHOC_CERT_CONF, "-extensions", "v3_ca", "-signkey", key, "-out", self.getDvsniCertFile(nonce), "-in", csr]

        
        #subprocess.call(["openssl", "x509", "-req", "-days", "21", "-extfile", CHOC_CERT_CONF, "-extensions", "v3_ca", "-signkey", key, "-out", self.getDvsniCertFile(nonce), "-in", csr], stdout=open("/dev/null", 'w'), stderr=open("/dev/null", 'w'))


    def createCHOC_CERT_CONF(self, name, ext):
        """
        Generates an OpenSSL certificate configuration file
        """

        text = " # OpenSSL configuration file. \n\n \
        [ v3_ca ] \n \
        basicConstraints  = CA:TRUE\n\
        subjectAltName = @alt_names\n\n\
        [ alt_names ]\n"

        with open(CHOC_CERT_CONF, 'w') as f:
            f.write(text)
            f.write("DNS:1 = %s\n" % name)
            f.write("DNS:2 = %s\n" % ext)

    def generateExtension(self, r, s):
        """
        Generates z to be placed in certificate extension

        r:    byte array
        s:    byte array

        result: returns z + INVALID_EXT
        """
        h = hashlib.new('sha256')
        h.update(r)
        h.update(s)
        
        return h.hexdigest() + INVALID_EXT

    def byteToHex(self, byteStr):
        """
        Converts binary array to hex string

        byteStr:  byte array

        result: returns hex representation of byteStr
        """

        return ''.join(["%02X" % ord(x) for x in byteStr]).strip()


    def cleanup(self):
        """
        Remove all temporary changes necessary to perform the challenge

        configurator:  Configurator object
        listSNITuple:  The initial challenge tuple

        result: Apache server is restored to the pre-challenge state
        """
        self.configurator.revert_challenge_config()
        self.configurator.restart(True)
    
    def generate_response(self):
        """
        Generates a response for a completed challenge
        """
        if self.s:
            return {"type":"dvsni", "s":self.s}

        logger.error("DVSNI Challenge was not completed before calling generate_response")
        return None

    #main call
    def perform(self, quiet=False):
        """
        Sets up and reloads Apache server to handle SNI challenges

        listSNITuple:  List of tuples with form (addr, r, nonce)
                       addr (string), r (base64 string), nonce (hex string)
        key:           string - File path to key
        configurator:  Configurator obj
        """
        # Save any changes to the configuration as a precaution
        # About to make temporary changes to the config
        self.configurator.save()

        addresses = []
        default_addr = "*:443"
        for tup in self.listSNITuple:
            vhost = self.configurator.choose_virtual_host(tup[0])
            if vhost is None:
                print "No vhost exists with servername or alias of:", tup[0]
                print "No _default_:443 vhost exists"
                print "Please specify servernames in the Apache config"
                return None

            if not self.configurator.make_server_sni_ready(vhost, default_addr):
                return None

            for a in vhost.addrs:
                if "_default_" in a:
                    addresses.append([default_addr])
                    break
            else:
                addresses.append(vhost.addrs)

        # Generate S
        s = Random.get_random_bytes(S_SIZE)
        # Create all of the challenge certs
        for tup in self.listSNITuple:
            # Need to decode from base64
            r = jose.b64decode_url(tup[1])
            ext = self.generateExtension(r, s)
            self.createChallengeCert(tup[0], ext, tup[2], self.key)

        self.modifyApacheConfig(self.configurator.user_config_file, addresses)
        # Save reversible changes and restart the server
        self.configurator.save("SNI Challenge", True)
        self.configurator.restart(quiet)

        self.s = jose.b64encode_url(s)
        return self.s

# This main function is just used for testing
def main():
    key = path.abspath("/home/ubuntu/key.pem")
    csr = path.abspath("/home/ubuntu/req.pem")
    logger.setLogger(logger.FileLogger(sys.stdout))
    logger.setLogLevel(logger.INFO)

    testkey = M2Crypto.RSA.load_key(key)
    
    #r = Random.get_random_bytes(S_SIZE)
    r = "testValueForR"
    #nonce = Random.get_random_bytes(NONCE_SIZE)
    nonce = "nonce"
    r2 = "testValueForR2"
    nonce2 = "nonce2"
    
    r = jose.b64encode_url(r)
    r2 = jose.b64encode_url(r2)

    #ans = dns.resolver.query("google.com")
    #print ans.rrset
    #return
    #the second parameter is ignored
    #https://www.dlitz.net/software/pycrypto/api/current/
    #y = testkey.public_encrypt(r, M2Crypto.RSA.pkcs1_oaep_padding)
    #y2 = testkey.public_encrypt(r2, M2Crypto.RSA.pkcs1_oaep_padding)

    nonce = binascii.hexlify(nonce)
    nonce2 = binascii.hexlify(nonce2)
    
    config = configurator.Configurator()

    challenges = [("client.theobroma.info", r, nonce), ("foo.theobroma.info",r2, nonce2)]
    #challenges = [("127.0.0.1", y, nonce, "1.3.3.7"), ("localhost", y2, nonce2, "1.3.3.7")]
    sni_chall = SNI_Challenge(challenges,  key, config)
    if sni_chall.perform():
        # Waste some time without importing time module... just for testing
        for i in range(0, 12000):
            if i % 2000 == 0:
                print "Waiting:", i

        #print "Cleaning up"
        #sni_chall.cleanup()
    else:
        print "Failed SNI challenge..."

if __name__ == "__main__":
    main()
