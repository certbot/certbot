# Apache server root directory
SERVER_ROOT = "/etc/apache2/"
# Configuration file directory for trustify
CONFIG_DIR = "/etc/trustify/"
# Working directory for trustify
WORK_DIR = "/var/lib/trustify/"
# Directory where configuration backups are stored
BACKUP_DIR = WORK_DIR + "backups/"

# Used by openssl to sign challenge certificate with trustify extension
CHOC_CERT_CONF = CONFIG_DIR + "choc_cert_extensions.cnf"
# Contains standard Apache SSL directives
OPTIONS_SSL_CONF = CONFIG_DIR + "options-ssl.conf"
# Temporary file for challenge virtual hosts
APACHE_CHALLENGE_CONF = CONFIG_DIR + "choc_sni_cert_challenge.conf"
# Modified files intended to be reset (for challenges/tmp config changes)
MODIFIED_FILES = BACKUP_DIR + "modified_files"
# Byte size of S and Nonce
S_SIZE = 32
NONCE_SIZE = 32

# bits of hashcash to generate
difficulty = 23 

# Trustify cert and chain files
cert_file = "cert.pem"
chain_file = "chain.pem"
