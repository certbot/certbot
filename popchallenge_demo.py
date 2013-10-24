from trustify.protocol import chocolate_pb2 
from popchallenge import *

m = chocolate_pb2.chocolatemessage()
r = chocolate_pb2.chocolatemessage()

skid, snonce = make_challenge(open("/tmp/pub.pem"))
m.challenge.add(name="what-is-the-frequency", type=m.ProofOfPossession, data=(skid, snonce))

for challenge in m.challenge:
    pcr = POPChallengeResponder(*challenge.data)
    pcr.find_priv(["/tmp/pub.pem", "/tmp/decoy.pem", "/tmp/falkdjaslkdj", "/tmp/priv.pem"])
    assert pcr.privkey
    cnonce, sig = pcr.respond_challenge()
    r.completedchallenge.add(name=challenge.name, type=r.ProofOfPossession, data=(cnonce,sig))

for completedchallenge in r.completedchallenge:
    # If there's actually more than one then we'd need to store and use
    # multiple different values of snonce.
    print verify_challenge_response(open("/tmp/pub.pem").read(), snonce, *completedchallenge.data)
