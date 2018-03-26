#!/bin/sh

DEFAULT_CONF=/etc/postfix/main.cf
BACKUP_TLS_CONF=/etc/postfix/tls.cf.bk
BACKUP_NO_TLS_CONF=/etc/postfix/no_tls.cf.bk

DEFAULT_POLICY=/etc/postfix/starttls_everywhere_policy
BACKUP_POLICY=/etc/postfix/starttls_everywhere_policy.bk

setup() {
    ### Certbot setup
    ln -sf "/opt/certbot-postfix/testdata/certificates" /etc/certificates

    # Postconf things for testing purposes.
    postconf -e smtpd_use_tls=no
    postconf -e smtpd_tls_received_header=yes
    postconf -e smtputf8_enable=no
    postconf -e disable_dns_lookups=yes
    postconf -e myhostname=$HOSTNAME
    newaliases
}

install_certs() {
    # If certs alrady installed, restore from backup.
    if [ -f $BACKUP_TLS_CONF ]; then
        cp $BACKUP_TLS_CONF $DEFAULT_CONF
        postfix reload
        exit 0
    fi
    cp $DEFAULT_CONF $BACKUP_NO_TLS_CONF

    # Install certs via certbot!
    certbot install --installer certbot-postfix:postfix --cert-path /etc/certificates/valid.crt --key-path /etc/certificates/valid.key -d valid.example-recipient.com

    # Back up this installation!
    cp $DEFAULT_CONF $BACKUP_TLS_CONF
}

uninstall_certs() {
    # We shouldn't have to do anything other than
    # restore the original backup version.
    if [ -f $BACKUP_NO_TLS_CONF ]; then
        cp $BACKUP_NO_TLS_CONF $DEFAULT_CONF
        postfix reload
        exit 0
    fi
}

set_policy() {
    touch $DEFAULT_POLICY
    cp $DEFAULT_POLICY $BACKUP_POLICY
    postconf -e smtp_tls_policy_maps=hash:$DEFAULT_POLICY
    echo "$1" > $DEFAULT_POLICY
    postfix reload
}

restore_policy() {
    cp $BACKUP_POLICY $DEFAULT_POLICY
}
