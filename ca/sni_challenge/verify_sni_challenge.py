import M2Crypto
import sni_support
import hmac
import hashlib

S_SIZE = 20

def check(one, two, three, four, five):
    print "done"
    return 0

def byteToHex(byteStr):
    return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

def check_challenge_value(ext_value, r):
    s = ext_value[0:S_SIZE]
    mac = ext_value[S_SIZE:]
    expected_mac = hmac.new(r, str(s), hashlib.sha256).digest()

    #print "s: ", byteToHex(s)
    #print "mac: ", byteToHex(mac)
    #print "expected_mac: ", byteToHex(expected_mac)
    #print type(mac)
    #print type(expected_mac)

    if mac == expected_mac:
        return True
    return False 

def verify_challenge(address, r, nonce):
    sni_name = nonce + ".chocolate"

    context = M2Crypto.SSL.Context()
    context.set_allow_unknown_ca(True)
    context.set_verify(M2Crypto.SSL.verify_none, 4)

    conn = M2Crypto.SSL.Connection(context)
    sni_support.set_sni_ext(conn.ssl, sni_name)
    conn.connect((address, 443))

    cert_chain = conn.get_peer_cert_chain()
    
    #Ensure certificate chain form is correct
    if len(cert_chain) != 1:
        return False, "Incorrect number of certificates in chain"

    for i in range(0,cert_chain[0].get_ext_count()):
        ext = cert_chain[0].get_ext_at(i)

        if sni_support.get_nid(ext.x509_ext) == 0:

            valid = check_challenge_value(sni_support.get_unknown_value(ext.x509_ext), r)
            if valid:
                return True, "Challenge completed successfully"
            else:
                return False, "Certificate extension does not check out"

    return False, "Chocolate extension not included in certificate"

def main():
    #Testing the example sni_challenge
    from Crypto.PublicKey import RSA

    nonce = "nonce"
    testkey = RSA.importKey(open("testing.key").read())

    #the second parameter is ignored
    #https://www.dlitz.net/software/pycrypto/api/current/
    encryptedValue = testkey.encrypt('0x12345678', 0)
    valid, response = verify_challenge("127.0.0.1", '0x12345678', nonce)
    print response

if __name__ == "__main__":
    main()
