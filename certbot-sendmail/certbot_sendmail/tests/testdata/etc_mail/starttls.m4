divert(-1)dnl
####################################################################
####################################################################
divert(0)dnl
VERSIONID(`$Id: starttls.m4,v 8.15.2-10 2018-01-13 23:43:05 cowboy Exp $')
dnl #
dnl #---------------------------------------------------------------------
dnl # Bring in Autoconf results
dnl #---------------------------------------------------------------------
ifdef(`sm_version', `dnl',
`include(`/usr/share/sendmail/cf/debian/autoconf.m4')dnl')
dnl #
dnl # Check to see if inclusion is valid (version >= 8.11.0, tls enabled)
ifelse(eval(sm_version_math >= 527104), `1', `dnl
ifelse(sm_enable_tls, `yes', `dnl
dnl #
dnl # To support shared keyfiles, we need them to be group readable
dnl #
define(`confDONT_BLAME_SENDMAIL',dnl
	defn(`confDONT_BLAME_SENDMAIL')`,GroupReadableKeyFile')dnl
dnl #
dnl #             ...Do not touch anything above this line...
dnl #
dnl # Set a more reasonable timeout on negotiation
dnl #
define(`confTO_STARTTLS',     `2m')dnl   # <= EDIT
dnl #
dnl # CA directory - CA certs should be herein
define(`confCACERT_PATH',     `/etc/ssl/certs')dnl   # <= EDIT
dnl #
dnl # CA file (may be the same as client/server certificate)
define(`confCACERT',           `/etc/mail/tls/sendmail-server.crt')dnl   # <= EDIT
dnl #
dnl # Certificate Revocation List
define(`confCRL',              `')dnl   # <= EDIT
dnl # CRL not found...  do not issue warnings on it!
undefine(`confCRL')dnl
dnl #
dnl # Server certificate/key (can be in the same file, and shared w/client)
dnl # NOTE: The key must *NOT* be encrypted !!!
define(`confSERVER_CERT',     `/etc/mail/tls/sendmail-server.crt')dnl   # <= EDIT
define(`confSERVER_KEY',      `/etc/mail/tls/sendmail-common.key')dnl   # <= EDIT
dnl #
dnl # Client certificate/key (can be in the same file, and shared w/server)
dnl # NOTE: The key must *NOT* be encrypted !!!
define(`confCLIENT_CERT',     `/etc/mail/tls/sendmail-client.crt')dnl   # <= EDIT
define(`confCLIENT_KEY',      `/etc/mail/tls/sendmail-common.key')dnl   # <= EDIT
dnl #
dnl # DH parameters
define(`confDH_PARAMETERS',   `/etc/mail/tls/sendmail-common.prm')dnl # <= EDIT
dnl #
dnl # Optional settings
define(`confTLS_SRV_OPTIONS', `V')dnl   # <= EDIT
dnl #
')')dnl
