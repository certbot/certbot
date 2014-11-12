# Apache server root directory
SERVER_ROOT = "/etc/apache2/"
# Configuration file directory for letsencrypt
CONFIG_DIR = "/etc/letsencrypt/"
# Working directory for letsencrypt
WORK_DIR = "/var/lib/letsencrypt/"
# Directory where configuration backups are stored
BACKUP_DIR = WORK_DIR + "backups/"
# Replaces MODIFIED_FILES, directory where temp checkpoint is created
TEMP_CHECKPOINT_DIR = WORK_DIR + "temp_checkpoint/"
# Directory used before a permanent checkpoint is finalized
IN_PROGRESS_DIR = BACKUP_DIR + "IN_PROGRESS/"
# Directory where all certificates/keys are stored - used for easy revocation
CERT_KEY_BACKUP = WORK_DIR + "keys-certs/"
# Where all keys should be stored
KEY_DIR = SERVER_ROOT + "ssl/"
# Certificate storage
CERT_DIR = SERVER_ROOT + "certs/"

# Used by openssl to sign challenge certificate with letsencrypt extension
# No longer used
#CHOC_CERT_CONF = CONFIG_DIR + "choc_cert_extensions.cnf"
# Contains standard Apache SSL directives
OPTIONS_SSL_CONF = CONFIG_DIR + "options-ssl.conf"
# Let's Encrypt SSL vhost configuration extension
LE_VHOST_EXT = "-letsencrypt-ssl.conf"
# Temporary file for challenge virtual hosts
APACHE_CHALLENGE_CONF = CONFIG_DIR + "LE_dvsni_cert_challenge.conf"

# Byte size of S and Nonce
S_SIZE = 32
NONCE_SIZE = 16

# Key Sizes
RSA_KEY_SIZE = 2048

# bits of hashcash to generate
difficulty = 23 

# Let's Encrypt cert and chain files
CERT_PATH = CERT_DIR + "letsencrypt-cert.pem"
CHAIN_PATH = CERT_DIR + "letsencrypt-chain.pem"

#Invalid Extension                                                              
INVALID_EXT = ".acme.invalid"

# Challenge Preferences Dict for currently supported challenges
CHALLENGE_PREFERENCES = ["dvsni", "recoveryToken"]

# Mutually Exclusive Challenges - only solve 1
EXCLUSIVE_CHALLENGES = [set(["dvsni", "simpleHttps"])]

# Rewrite rule arguments used for redirections to https vhost
REWRITE_HTTPS_ARGS = ["^.*$", "https://%{SERVER_NAME}%{REQUEST_URI}", "[L,R=permanent]"]
