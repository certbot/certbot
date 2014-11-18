from trustify.protocol import chocolate_pb2
from popchallenge import *

# openssl genrsa 2048 > /tmp/priv.pem
# openssl genrsa 2048 > /tmp/decoy.pem
# openssl rsa -in /tmp/priv.pem -pubout > /tmp/pub.pem

m = chocolate_pb2.chocolatemessage()
r = chocolate_pb2.chocolatemessage()

skid, snonce = make_challenge(open("/tmp/pub.pem"))
m.challenge.add(name="what-is-the-frequency", type=m.ProofOfPossession, data=(skid, snonce))

for challenge in m.challenge:
    if challenge.type == m.ProofOfPossession:
        pcr = POPChallengeResponder(*challenge.data)
        pcr.find_priv(["/tmp/pub.pem", "/tmp/decoy.pem", "/tmp/falkdjaslkdj", "/tmp/priv.pem"])
        assert pcr.privkey
        cnonce, sig = pcr.respond_challenge()
        r.completedchallenge.add(name=challenge.name, type=r.ProofOfPossession, data=(cnonce,sig))

for completedchallenge in r.completedchallenge:
    # If there's actually more than one then we'd need to store and use
    # multiple different values of snonce.
    if completedchallenge.type == r.ProofOfPossession:
        print verify_challenge_response(open("/tmp/pub.pem").read(), snonce, *completedchallenge.data)
