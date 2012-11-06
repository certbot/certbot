# The name that the server expects to be referred to by.
chocolate_server_name = "ca.theobroma.info"

# The shortest length in bits of an acceptable RSA modulus.
min_keysize = 2048

# The number of bits of hashcash that a client must provide with
# a new request.
difficulty = 23

# The number of seconds that the server asks the client to wait, at
# a time, when a request is still being processed.
polldelay = 4

# The maximum number of subject names in a request.
max_names = 20

# The maximum size in bytes of a CSR.
max_csr_size = 20480

# The expiry times of sessions, challenges, and hashcash, in seconds.
maximum_session_age = 100
maximum_challenge_age = 600
hashcash_expiry = 60*60

# Extra names that the CA refuses to issue for, apart from those in
# the blacklist table in the database.
extra_name_blacklist = ["eff.org", "www.eff.org"]

# Name of file containing cert chain
cert_chain_file = "demoCA/cacert.pem"
debug = True
