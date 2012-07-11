import M2Crypto
from Crypto import Random
import sni_support
import hmac
import hashlib
import binascii

S_SIZE = 32
NONCE_SIZE = 32

def check(one, two, three, four, five):
    print "done"
    return 0

def byteToHex(byteStr):
    return ''.join(["%02X" % ord(x) for x in byteStr]).strip()

def check_challenge_value(ext_value, r):
    """
    Checks that a challenge response actually passes the challenge

    ext_value:      string returned by client-webserver's X.509 cert
                    chocolate extension
    r:              secret random key (binary string) chosen by server-CA
    """
    s = ext_value[0:S_SIZE]
    mac = ext_value[S_SIZE:]
    expected_mac = hmac.new(r, str(s), hashlib.sha256).digest()

    #print "s: ", byteToHex(s)
    #print "mac: ", byteToHex(mac)
    #print "expected_mac: ", byteToHex(expected_mac)

    if mac == expected_mac:
        return True
    return False 

def verify_challenge(address, r, nonce):
    """
    Verifies an SNI challenge at address (assumes port 443)

    address:    string host (e.g. "127.0.0.1")
    r:          secret random key (binary string)
    nonce:      ascii string of nonce (e.g. "66f58cfb...")

    returns (result, reason)
    result:     True/False for passed/failed verification
    reason:     Human-readable string describing reason for result
    """
    sni_name = nonce + ".chocolate"

    context = M2Crypto.SSL.Context()
    context.set_allow_unknown_ca(True)
    context.set_verify(M2Crypto.SSL.verify_none, 4)

    #Consider placing try/catch block around wrong host exception
    #or fix M2Crypto to handle SANs appropriately
    M2Crypto.SSL.Connection.postConnectionCheck = None

    conn = M2Crypto.SSL.Connection(context)
    sni_support.set_sni_ext(conn.ssl, sni_name)
    try:
        conn.connect((address, 443))
    except:
        return False, "Connection to SSL Server failed"

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

    nonce = Random.get_random_bytes(NONCE_SIZE)
    nonce = "nonce"
    nonce2 = "nonce2"
  
    r = Random.get_random_bytes(NONCE_SIZE)
    r = "testValueForR"
    r2 = "testValueForR2"

    nonce = binascii.hexlify(nonce)
    nonce2 = binascii.hexlify(nonce2)

    valid, response = verify_challenge("example.com", r, "33947bb5dd81f17f67305cb90aa5b8b5e95442e8ed4e78567092a63d04eb3db4")
    print response
    valid, response = verify_challenge("www.example.com", r2, "no123809214unce2")
    print response
if __name__ == "__main__":
    main()
